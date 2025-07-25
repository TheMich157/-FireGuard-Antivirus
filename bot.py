import os
import requests
import discord
from discord import app_commands
from discord.ext import commands

API_URL = os.environ.get("API_URL", "https://fireguard.aigenres.xyz")
ADMIN_LICENSE = os.environ.get("ADMIN_LICENSE")
TOKEN = os.environ.get("DISCORD_BOT_TOKEN")

intents = discord.Intents.default()

bot = commands.Bot(command_prefix="!", intents=intents)


def post_api(path: str):
    headers = {}
    if ADMIN_LICENSE:
        headers["X-License"] = ADMIN_LICENSE
    try:
        requests.post(f"{API_URL}{path}", headers=headers, timeout=5)
        return True
    except Exception:
        return False


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user}")
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print("Sync failed", e)


@bot.tree.command(name="license", description="Send license info")
@app_commands.describe(username="Username", key="License key")
async def license_cmd(interaction: discord.Interaction, username: str, key: str):
    embed = discord.Embed(title="New License", color=0x2ecc71)
    embed.add_field(name="User", value=username, inline=False)
    embed.add_field(name="License", value=f"`{key}`", inline=False)
    await interaction.response.send_message(embed=embed)


@bot.tree.command(name="restart", description="Restart the FireGuard server")
async def restart_cmd(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    if post_api("/api/control/restart"):
        await interaction.followup.send("Server restart initiated.")
    else:
        await interaction.followup.send("Failed to contact server.")


@bot.tree.command(name="shutdown", description="Shutdown the FireGuard server")
async def shutdown_cmd(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    if post_api("/api/control/shutdown"):
        await interaction.followup.send("Server shutdown initiated.")
    else:
        await interaction.followup.send("Failed to contact server.")


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("DISCORD_BOT_TOKEN missing")
    bot.run(TOKEN)