"""Agent process management utilities."""

from __future__ import annotations

import logging
import multiprocessing as mp
import os
import signal
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

import discord

from .utils import SimpleVectorStore, ensure_directory

LOGGER = logging.getLogger(__name__)


def _agent_worker(agent_id: int, name: str, vector_path: str, discord_token: str | None) -> None:
    """Run inside a child process to keep the agent alive."""
    logging.basicConfig(level=logging.INFO)
    store = SimpleVectorStore(Path(vector_path))
    store.add(f"Agent {name} started")
    LOGGER = logging.getLogger(f"Agent-{agent_id}")

    intents = discord.Intents.default()
    intents.messages = True
    intents.message_content = True
    client = discord.Client(intents=intents)

    @client.event
    async def on_ready():
        LOGGER.info("Agent %s connected to Discord as %s", name, client.user)

    @client.event
    async def on_message(message: discord.Message):
        if message.author.bot:
            return
        store.add(message.content)
        await message.channel.send(f"{name} received your message!")

    if discord_token:
        client.run(discord_token)
    else:
        LOGGER.warning("No Discord token configured for %s; running idle loop", name)
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            LOGGER.info("Agent %s exiting", name)


@dataclass
class AgentProcess:
    process: mp.Process
    agent_id: int
    vector_path: str


class AgentRuntimeManager:
    """Keeps track of background processes spawned for agents."""

    def __init__(self) -> None:
        self._processes: Dict[int, AgentProcess] = {}

    def start_agent(self, agent_id: int, name: str, vector_path: str, discord_token: str | None = None) -> None:
        if agent_id in self._processes and self._processes[agent_id].process.is_alive():
            return
        ensure_directory(Path(vector_path).parent)
        proc = mp.Process(target=_agent_worker, args=(agent_id, name, vector_path, discord_token), daemon=True)
        proc.start()
        self._processes[agent_id] = AgentProcess(process=proc, agent_id=agent_id, vector_path=vector_path)

    def stop_agent(self, agent_id: int) -> None:
        entry = self._processes.get(agent_id)
        if not entry:
            return
        process = entry.process
        if process.is_alive():
            os.kill(process.pid, signal.SIGTERM)
            process.join(timeout=5)
            if process.is_alive():
                process.kill()
        self._processes.pop(agent_id, None)

    def status(self, agent_id: int) -> str:
        entry = self._processes.get(agent_id)
        if not entry:
            return "stopped"
        return "running" if entry.process.is_alive() else "stopped"

    def stop_all(self) -> None:
        for agent_id in list(self._processes.keys()):
            self.stop_agent(agent_id)


def load_launcher_config(path: Path) -> Dict[str, Dict[str, str]]:
    from configparser import ConfigParser

    parser = ConfigParser()
    parser.read(path)
    configs: Dict[str, Dict[str, str]] = {}
    for section in parser.sections():
        configs[section] = dict(parser.items(section))
    return configs


def launch_agents_from_file(path: Path) -> AgentRuntimeManager:
    manager = AgentRuntimeManager()
    configs = load_launcher_config(path)
    for section, config in configs.items():
        agent_id = int(config.get("agent_id", "0") or 0)
        name = config.get("name", section)
        vector_path = config.get("vector_path", f"data/memory/{agent_id or section}.json")
        discord_token = config.get("discord_token")
        manager.start_agent(agent_id or hash(section) % 10000, name, vector_path, discord_token)
    return manager


__all__ = ["AgentRuntimeManager", "launch_agents_from_file"]
