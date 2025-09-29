"""Flask application that powers the OpenShapes management panel and API."""

from __future__ import annotations

import datetime as dt
import json
import time
import uuid
from pathlib import Path
from typing import Optional

from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from .models import (
    Agent,
    AgentConfig,
    Subject,
    SubjectLimit,
    SubjectUsage,
    Usage,
    UsageCounter,
    User,
    create_session_factory,
)
from .proc import AgentRuntimeManager
from .utils import ConfigLoader, SimpleVectorStore, generate_api_key, verify_signature

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "app.ini"


# Application factory -------------------------------------------------------

def create_app(config_path: Optional[Path] = None) -> Flask:
    config_path = Path(config_path or CONFIG_PATH)
    config_loader = ConfigLoader(config_path)
    app = Flask(__name__, template_folder="templates")
    app.config["SECRET_KEY"] = config_loader.get("flask", "secret_key", fallback="change-me")
    app.config["CONFIG_PATH"] = config_path

    database_url = config_loader.get("database", "url", fallback="sqlite:///openshapes.db")
    session_factory = create_session_factory(database_url)
    app.session_factory = session_factory  # type: ignore[attr-defined]

    login_manager = LoginManager(app)
    login_manager.login_view = "login"

    superadmin_discord_id = config_loader.get("discord", "superadmin_id", fallback="")
    app.config["SUPERADMIN_DISCORD_ID"] = superadmin_discord_id
    app.config["API_BASE_URL"] = config_loader.get("openai", "base_url", fallback="https://api.openai.com/v1")
    app.config["DEFAULT_MODEL"] = config_loader.get("openai", "default_model", fallback="gpt-3.5-turbo")
    app.config["DEFAULT_API_KEY"] = config_loader.get("openai", "api_key", fallback="")

    runtime_manager = AgentRuntimeManager()
    app.extensions["agent_runtime"] = runtime_manager

    @login_manager.user_loader
    def load_user(user_id: str) -> Optional[User]:  # pragma: no cover - delegated to flask-login
        session = session_factory()
        try:
            return session.get(User, int(user_id))
        finally:
            session.close()

    @app.before_request
    def create_session():
        g.db = session_factory()

    @app.teardown_request
    def shutdown_session(exception: Optional[BaseException]):
        session = getattr(g, "db", None)
        if session is None:
            return
        try:
            if exception is None:
                session.commit()
            else:
                session.rollback()
        finally:
            session.close()
            g.db = None

    # Helpers --------------------------------------------------------------

    def require_superadmin() -> None:
        if not current_user.is_authenticated or not current_user.is_superadmin:
            abort(403)

    def get_subject_for_request(body: bytes) -> Subject:
        session = g.db
        subject_opaque_id = request.headers.get("X-Subject-ID")
        signature = request.headers.get("X-Signature")
        if not subject_opaque_id or not signature:
            abort(401, description="Missing subject headers")
        subject = (
            session.query(Subject)
            .filter(Subject.opaque_id == subject_opaque_id, Subject.is_active.is_(True))
            .one_or_none()
        )
        if subject is None:
            abort(403, description="Subject not found or inactive")
        if not verify_signature(subject.hmac_secret, subject.opaque_id, body, signature):
            abort(403, description="Invalid signature")
        return subject

    def get_or_create_subject_usage(subject: Subject) -> SubjectUsage:
        session = g.db
        now = dt.datetime.utcnow()
        usage = (
            session.query(SubjectUsage)
            .filter_by(subject_id=subject.id, month=now.month, year=now.year)
            .one_or_none()
        )
        if usage is None:
            usage = SubjectUsage(subject_id=subject.id, month=now.month, year=now.year)
            session.add(usage)
            session.flush()
        return usage

    def enforce_quota(subject: Subject, usage: SubjectUsage, tokens: int = 0, images: int = 0) -> None:
        limits = subject.limits
        if limits is None:
            return
        if limits.monthly_token_limit and usage.tokens_used + tokens > limits.monthly_token_limit:
            abort(429, description="Token quota exceeded")
        if limits.monthly_image_limit and usage.images_generated + images > limits.monthly_image_limit:
            abort(429, description="Image quota exceeded")

    def agent_vector_store(agent: AgentConfig) -> SimpleVectorStore:
        path = Path(agent.vector_path)
        if not path.is_absolute():
            path = Path(__file__).resolve().parent.parent / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return SimpleVectorStore(path)

    def agent_for_id(agent_id: Optional[int]) -> tuple[AgentConfig, Optional[Agent]]:
        session = g.db
        if agent_id:
            agent_config = session.get(AgentConfig, agent_id)
        else:
            agent_config = session.query(AgentConfig).filter_by(is_enabled=True).first()
        if agent_config is None:
            abort(404, description="Agent not found")
        agent_entry = session.query(Agent).filter_by(config_id=agent_config.id).first()
        return agent_config, agent_entry

    def runtime() -> AgentRuntimeManager:
        return app.extensions["agent_runtime"]

    # Authentication -------------------------------------------------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            session = g.db
            user = session.query(User).filter_by(username=username).one_or_none()
            if not user or not user.is_active or not check_password_hash(user.password_hash, password):
                flash("Invalid credentials", "danger")
            else:
                super_id = app.config.get("SUPERADMIN_DISCORD_ID")
                if super_id and user.discord_id == super_id and not user.is_superadmin:
                    user.is_superadmin = True
                    session.add(user)
                login_user(user)
                return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("login"))

    # Dashboard ------------------------------------------------------------

    @app.route("/")
    @login_required
    def dashboard():
        session = g.db
        counter = UsageCounter(session)
        totals = counter.totals()
        agents = session.query(AgentConfig).all()
        subjects = session.query(Subject).count()
        users = session.query(User).count()
        config_file = app.config["CONFIG_PATH"]
        try:
            with open(config_file, "r", encoding="utf-8") as fh:
                config_text = fh.read()
        except FileNotFoundError:
            config_text = ""
        statuses = {agent.id: runtime().status(agent.id) for agent in agents}
        return render_template(
            "dashboard.html",
            totals=totals,
            agents=agents,
            subjects=subjects,
            users=users,
            statuses=statuses,
            config_text=config_text,
        )

    @app.route("/config", methods=["POST"])
    @login_required
    def save_config():
        require_superadmin()
        config_text = request.form.get("config_text", "")
        config_file = app.config["CONFIG_PATH"]
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, "w", encoding="utf-8") as fh:
            fh.write(config_text)
        flash("Configuration updated", "success")
        return redirect(url_for("dashboard"))

    # User management -----------------------------------------------------

    @app.route("/users")
    @login_required
    def users_view():
        require_superadmin()
        session = g.db
        users = session.query(User).all()
        return render_template("users.html", users=users)

    @app.route("/users/new", methods=["GET", "POST"])
    @login_required
    def user_create():
        require_superadmin()
        session = g.db
        if request.method == "POST":
            username = request.form["username"].strip()
            password = request.form["password"]
            discord_id = request.form.get("discord_id") or None
            is_super = bool(request.form.get("is_superadmin"))
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                api_key=generate_api_key(),
                is_superadmin=is_super,
                discord_id=discord_id,
            )
            session.add(user)
            flash("User created", "success")
            return redirect(url_for("users_view"))
        return render_template("user_form.html", user=None)

    @app.route("/users/<int:user_id>", methods=["GET", "POST"])
    @login_required
    def user_edit(user_id: int):
        require_superadmin()
        session = g.db
        user = session.get(User, user_id)
        if not user:
            abort(404)
        if request.method == "POST":
            user.username = request.form["username"].strip()
            password = request.form.get("password")
            if password:
                user.password_hash = generate_password_hash(password)
            user.discord_id = request.form.get("discord_id") or None
            user.is_active = bool(request.form.get("is_active"))
            user.is_superadmin = bool(request.form.get("is_superadmin"))
            flash("User updated", "success")
            return redirect(url_for("users_view"))
        return render_template("user_form.html", user=user)

    @app.route("/users/<int:user_id>/reset", methods=["POST"])
    @login_required
    def user_reset_api(user_id: int):
        require_superadmin()
        session = g.db
        user = session.get(User, user_id)
        if not user:
            abort(404)
        user.api_key = generate_api_key()
        flash("API key reset", "success")
        return redirect(url_for("users_view"))

    @app.route("/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    def user_delete(user_id: int):
        require_superadmin()
        session = g.db
        user = session.get(User, user_id)
        if not user:
            abort(404)
        session.delete(user)
        flash("User removed", "success")
        return redirect(url_for("users_view"))

    # Subject management --------------------------------------------------

    @app.route("/subjects")
    @login_required
    def subjects_view():
        require_superadmin()
        session = g.db
        subjects = session.query(Subject).all()
        return render_template("subjects.html", subjects=subjects)

    @app.route("/subjects/new", methods=["GET", "POST"])
    @login_required
    def subject_create():
        require_superadmin()
        session = g.db
        if request.method == "POST":
            name = request.form["name"].strip()
            opaque_id = request.form["opaque_id"].strip()
            hmac_secret = request.form.get("hmac_secret") or generate_api_key()[:32]
            token_limit = int(request.form.get("monthly_token_limit") or 0)
            image_limit = int(request.form.get("monthly_image_limit") or 0)
            subject = Subject(name=name, opaque_id=opaque_id, hmac_secret=hmac_secret)
            session.add(subject)
            session.flush()
            if token_limit or image_limit:
                limit = SubjectLimit(
                    subject_id=subject.id,
                    monthly_token_limit=token_limit,
                    monthly_image_limit=image_limit,
                )
                session.add(limit)
            flash("Subject created", "success")
            return redirect(url_for("subjects_view"))
        return render_template("subject_form.html", subject=None)

    @app.route("/subjects/<int:subject_id>", methods=["GET", "POST"])
    @login_required
    def subject_edit(subject_id: int):
        require_superadmin()
        session = g.db
        subject = session.get(Subject, subject_id)
        if not subject:
            abort(404)
        if request.method == "POST":
            subject.name = request.form["name"].strip()
            subject.opaque_id = request.form["opaque_id"].strip()
            subject.hmac_secret = request.form.get("hmac_secret") or subject.hmac_secret
            subject.is_active = bool(request.form.get("is_active"))
            token_limit = int(request.form.get("monthly_token_limit") or 0)
            image_limit = int(request.form.get("monthly_image_limit") or 0)
            if subject.limits is None and (token_limit or image_limit):
                subject.limits = SubjectLimit(
                    monthly_token_limit=token_limit,
                    monthly_image_limit=image_limit,
                )
            elif subject.limits:
                subject.limits.monthly_token_limit = token_limit
                subject.limits.monthly_image_limit = image_limit
            flash("Subject updated", "success")
            return redirect(url_for("subjects_view"))
        return render_template("subject_form.html", subject=subject)

    @app.route("/subjects/<int:subject_id>/delete", methods=["POST"])
    @login_required
    def subject_delete(subject_id: int):
        require_superadmin()
        session = g.db
        subject = session.get(Subject, subject_id)
        if not subject:
            abort(404)
        session.delete(subject)
        flash("Subject removed", "success")
        return redirect(url_for("subjects_view"))

    # Agent management ----------------------------------------------------

    @app.route("/agents")
    @login_required
    def agents_view():
        require_superadmin()
        session = g.db
        agents = session.query(AgentConfig).all()
        statuses = {agent.id: runtime().status(agent.id) for agent in agents}
        return render_template("agents.html", agents=agents, statuses=statuses)

    @app.route("/agents/new", methods=["GET", "POST"])
    @login_required
    def agent_create():
        require_superadmin()
        session = g.db
        if request.method == "POST":
            name = request.form["name"].strip()
            base_url = request.form.get("base_url") or app.config["API_BASE_URL"]
            model = request.form.get("model") or app.config["DEFAULT_MODEL"]
            api_key = request.form.get("api_key") or app.config.get("DEFAULT_API_KEY") or None
            vector_path = request.form.get("vector_path") or f"data/memory/{name.replace(' ', '_').lower()}.json"
            config_data = {
                "instructions": request.form.get("instructions", ""),
                "discord_token": request.form.get("discord_token") or None,
            }
            agent_config = AgentConfig(
                name=name,
                description=request.form.get("description"),
                config=config_data,
                base_url=base_url,
                model=model,
                api_key=api_key,
                vector_path=vector_path,
            )
            session.add(agent_config)
            session.flush()
            agent = Agent(config_id=agent_config.id, status="stopped")
            session.add(agent)
            flash("Agent created", "success")
            return redirect(url_for("agents_view"))
        return render_template("agent_form.html", agent=None)

    @app.route("/agents/<int:agent_id>", methods=["GET", "POST"])
    @login_required
    def agent_edit(agent_id: int):
        require_superadmin()
        session = g.db
        agent_config = session.get(AgentConfig, agent_id)
        if not agent_config:
            abort(404)
        if request.method == "POST":
            agent_config.name = request.form["name"].strip()
            agent_config.description = request.form.get("description")
            agent_config.base_url = request.form.get("base_url") or app.config["API_BASE_URL"]
            agent_config.model = request.form.get("model") or app.config["DEFAULT_MODEL"]
            agent_config.api_key = request.form.get("api_key") or app.config.get("DEFAULT_API_KEY") or None
            agent_config.vector_path = request.form.get("vector_path") or agent_config.vector_path
            agent_config.config = {
                "instructions": request.form.get("instructions", ""),
                "discord_token": request.form.get("discord_token") or None,
            }
            flash("Agent updated", "success")
            return redirect(url_for("agents_view"))
        return render_template("agent_form.html", agent=agent_config)

    @app.route("/agents/<int:agent_id>/start", methods=["POST"])
    @login_required
    def agent_start(agent_id: int):
        require_superadmin()
        session = g.db
        agent_config = session.get(AgentConfig, agent_id)
        if not agent_config:
            abort(404)
        discord_token = agent_config.config.get("discord_token") if isinstance(agent_config.config, dict) else None
        runtime().start_agent(agent_config.id, agent_config.name, agent_config.vector_path, discord_token)
        agent = session.query(Agent).filter_by(config_id=agent_config.id).first()
        if agent:
            agent.status = "running"
            agent.last_heartbeat = dt.datetime.utcnow()
        flash("Agent started", "success")
        return redirect(url_for("agents_view"))

    @app.route("/agents/<int:agent_id>/stop", methods=["POST"])
    @login_required
    def agent_stop(agent_id: int):
        require_superadmin()
        session = g.db
        agent_config = session.get(AgentConfig, agent_id)
        if not agent_config:
            abort(404)
        runtime().stop_agent(agent_config.id)
        agent = session.query(Agent).filter_by(config_id=agent_config.id).first()
        if agent:
            agent.status = "stopped"
        flash("Agent stopped", "success")
        return redirect(url_for("agents_view"))

    @app.route("/agents/<int:agent_id>/memory")
    @login_required
    def agent_memory(agent_id: int):
        require_superadmin()
        session = g.db
        agent_config = session.get(AgentConfig, agent_id)
        if not agent_config:
            abort(404)
        store = agent_vector_store(agent_config)
        memories = store.all()
        return render_template("memory.html", agent=agent_config, memories=memories)

    @app.route("/agents/<int:agent_id>/delete", methods=["POST"])
    @login_required
    def agent_delete(agent_id: int):
        require_superadmin()
        session = g.db
        agent_config = session.get(AgentConfig, agent_id)
        if not agent_config:
            abort(404)
        runtime().stop_agent(agent_config.id)
        session.delete(agent_config)
        flash("Agent deleted", "success")
        return redirect(url_for("agents_view"))

    # OpenAI-compatible API -----------------------------------------------

    @app.post("/v1/chat/completions")
    def chat_completions():
        body = request.get_data(cache=False)
        subject = get_subject_for_request(body)
        payload = json.loads(body or b"{}")
        agent_id = payload.get("agent_id")
        agent_config, agent_entry = agent_for_id(agent_id)
        store = agent_vector_store(agent_config)
        completion_text = f"{agent_config.name} responding at {dt.datetime.utcnow().isoformat()}"
        store.add(completion_text)
        tokens = len(completion_text.split())

        session = g.db
        usage = get_or_create_subject_usage(subject)
        enforce_quota(subject, usage, tokens=tokens)
        usage.tokens_used += tokens
        agent_ref = agent_entry.id if agent_entry else None
        session.add(Usage(subject_id=subject.id, agent_id=agent_ref, tokens_used=tokens))

        response = {
            "id": f"chatcmpl-{uuid.uuid4().hex}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": agent_config.model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": completion_text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": tokens, "total_tokens": tokens},
        }
        return jsonify(response)

    @app.post("/v1/images/generations")
    def image_generations():
        body = request.get_data(cache=False)
        subject = get_subject_for_request(body)
        payload = json.loads(body or b"{}")
        n = int(payload.get("n", 1))
        agent_ref = None
        if payload.get("agent_id"):
            agent_config, agent_entry = agent_for_id(payload.get("agent_id"))
            agent_ref = agent_entry.id if agent_entry else None
        session = g.db
        usage = get_or_create_subject_usage(subject)
        enforce_quota(subject, usage, images=n)
        usage.images_generated += n
        session.add(Usage(subject_id=subject.id, agent_id=agent_ref, images_generated=n))
        data = [
            {
                "url": f"https://example.com/generated/{uuid.uuid4().hex}.png",
                "revised_prompt": None,
            }
            for _ in range(n)
        ]
        return jsonify({"created": int(time.time()), "data": data})

    return app


app = create_app()
