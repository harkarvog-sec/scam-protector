import discord
from discord.ext import commands
from discord import app_commands

import datetime
import os
import re
import sqlite3

# TOKEN
TOKEN = os.getenv("DISCORD_TOKEN")

# DATABASE
DB_FILE = "scam_protector.db"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def setup_database():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS server_config (
            guild_id INTEGER PRIMARY KEY,
            log_channel_id INTEGER,
            alert_channel_id INTEGER,
            general_channel_id INTEGER,
            min_account_age INTEGER DEFAULT 7,
            monitor_threshold INTEGER DEFAULT 30,
            alert_threshold INTEGER DEFAULT 60,
            ban_threshold INTEGER DEFAULT 80
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_risk (
            guild_id INTEGER,
            user_id INTEGER,
            score INTEGER DEFAULT 0,
            PRIMARY KEY (guild_id, user_id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS statistics (
            guild_id INTEGER PRIMARY KEY,
            banned INTEGER DEFAULT 0,
            alerts INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


setup_database()

# BOT
intents = discord.Intents.all()

bot = commands.Bot(
    command_prefix="!",
    intents=intents
)

# DATABASE HELPERS
def get_server_config(guild_id):
    conn = get_db()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM server_config
        WHERE guild_id = ?
        """,
        (guild_id,)
    )

    result = cursor.fetchone()

    conn.close()

    return result


def save_server_config(
    guild_id,
    log_channel_id,
    alert_channel_id,
    general_channel_id,
    min_account_age,
    monitor_threshold,
    alert_threshold,
    ban_threshold
):
    conn = get_db()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT OR REPLACE INTO server_config
        (
            guild_id,
            log_channel_id,
            alert_channel_id,
            general_channel_id,
            min_account_age,
            monitor_threshold,
            alert_threshold,
            ban_threshold
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            guild_id,
            log_channel_id,
            alert_channel_id,
            general_channel_id,
            min_account_age,
            monitor_threshold,
            alert_threshold,
            ban_threshold
        )
    )

    cursor.execute(
        """
        INSERT OR IGNORE INTO statistics
        (guild_id, banned, alerts)
        VALUES (?, 0, 0)
        """,
        (guild_id,)
    )

    conn.commit()
    conn.close()


def get_user_score(guild_id, user_id):
    conn = get_db()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT score
        FROM user_risk
        WHERE guild_id = ?
        AND user_id = ?
        """,
        (guild_id, user_id)
    )

    result = cursor.fetchone()

    conn.close()

    if result:
        return result["score"]

    return 0


def add_user_score(guild_id, user_id, amount):
    conn = get_db()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO user_risk
        (guild_id, user_id, score)
        VALUES (?, ?, ?)

        ON CONFLICT(guild_id, user_id)
        DO UPDATE SET score = score + ?
        """,
        (
            guild_id,
            user_id,
            amount,
            amount
        )
    )

    conn.commit()

    cursor.execute(
        """
        SELECT score
        FROM user_risk
        WHERE guild_id = ?
        AND user_id = ?
        """,
        (guild_id, user_id)
    )

    result = cursor.fetchone()

    conn.close()

    return result["score"]


def increment_banned(guild_id):
    conn = get_db()

    conn.execute(
        """
        UPDATE statistics
        SET banned = banned + 1
        WHERE guild_id = ?
        """,
        (guild_id,)
    )

    conn.commit()
    conn.close()


def increment_alerts(guild_id):
    conn = get_db()

    conn.execute(
        """
        UPDATE statistics
        SET alerts = alerts + 1
        WHERE guild_id = ?
        """,
        (guild_id,)
    )

    conn.commit()
    conn.close()

# SUSPICIOUS PATTERNS
SUSPICIOUS_USERNAME_WORDS = [
    "free",
    "nitro",
    "giveaway",
    "crypto",
    "bitcoin",
    "airdrop",
    "hack",
    "steamgift",
    "claim"
]


SUSPICIOUS_MESSAGE_WORDS = [
    "free nitro",
    "claim nitro",
    "free crypto",
    "free bitcoin",
    "double your money",
    "investment opportunity",
    "click this link",
    "claim your prize",
    "you won",
    "verify your account"
]


URL_PATTERN = re.compile(
    r"https?://[^\s]+",
    re.IGNORECASE
)

# ACCOUNT AGE
def get_account_age(member):
    now = datetime.datetime.now(
        datetime.timezone.utc
    )

    return now - member.created_at


def account_age_score(member, minimum_age):
    """
    Score account age according to the
    server's configured minimum account age.
    """

    age = get_account_age(member)

    if minimum_age <= 0:
        return 0

    # Extremely new accounts receive the
    # highest account-age risk.
    if age.days < 1:
        return 40

    # Less than half the configured minimum.
    if age.days < max(1, minimum_age // 2):
        return 30

    # Below the configured minimum.
    if age.days < minimum_age:
        return 20

    # Older but still relatively new.
    if age.days < minimum_age * 4:
        return 5

    return 0

# USERNAME SCORE
def username_score(member):
    username = (
        f"{member.name} {member.display_name}"
    ).lower()

    for word in SUSPICIOUS_USERNAME_WORDS:
        if word in username:
            return 20

    return 0

# PROFILE SCORE
def profile_score(member):
    score = 0

    if member.avatar is None:
        score += 5

    return score

# INITIAL MEMBER SCAN
def initial_scan(member, minimum_age):
    score = 0
    reasons = []

    age_points = account_age_score(
        member,
        minimum_age
    )

    if age_points:
        score += age_points

        reasons.append(
            f"Account age risk: +{age_points}"
        )

    username_points = username_score(member)

    if username_points:
        score += username_points

        reasons.append(
            f"Username risk: +{username_points}"
        )

    profile_points = profile_score(member)

    if profile_points:
        score += profile_points

        reasons.append(
            f"Profile risk: +{profile_points}"
        )

    return score, reasons

# MESSAGE SCAN
def message_score(message):
    score = 0
    reasons = []

    content = message.content.lower()

    for phrase in SUSPICIOUS_MESSAGE_WORDS:

        if phrase in content:

            score += 30

            reasons.append(
                f"Suspicious phrase detected: +30"
            )

            break

    urls = URL_PATTERN.findall(
        message.content
    )

    if urls:

        score += 20

        reasons.append(
            "Message contains URL: +20"
        )

    if len(message.mentions) >= 5:

        score += 30

        reasons.append(
            "Excessive mentions: +30"
        )

    if message.mention_everyone:

        score += 40

        reasons.append(
            "@everyone/@here abuse: +40"
        )

    return score, reasons

# CHANNEL HELPER
async def get_channel(guild, channel_id):

    if not channel_id:
        return None

    channel = guild.get_channel(
        channel_id
    )

    if channel:
        return channel

    try:
        return await bot.fetch_channel(
            channel_id
        )

    except (
        discord.NotFound,
        discord.Forbidden,
        discord.HTTPException
    ):
        return None

# PRIVATE SECURITY LOG
async def send_security_log(
    guild,
    embed
):
    config = get_server_config(
        guild.id
    )

    if not config:
        return

    channel = await get_channel(
        guild,
        config["log_channel_id"]
    )

    if not channel:
        return

    try:
        await channel.send(
            embed=embed
        )

    except discord.Forbidden:
        print(
            f"❌ Cannot send security log "
            f"in {guild.name}"
        )

# PUBLIC GENERAL NOTIFICATION
async def send_general_notification(
    guild,
    embed
):
    config = get_server_config(
        guild.id
    )

    if not config:
        return

    channel = await get_channel(
        guild,
        config["general_channel_id"]
    )

    if not channel:
        return

    try:
        await channel.send(
            embed=embed
        )

    except discord.Forbidden:
        print(
            f"❌ Cannot send general notification "
            f"in {guild.name}"
        )

# ALERT CHANNEL
async def send_security_alert(
    guild,
    embed
):
    config = get_server_config(
        guild.id
    )

    if not config:
        return

    channel = await get_channel(
        guild,
        config["alert_channel_id"]
    )

    if not channel:
        return

    try:
        await channel.send(
            embed=embed
        )

    except discord.Forbidden:
        print(
            f"❌ Cannot send security alert "
            f"in {guild.name}"
        )

# RISK PROCESSING
async def process_risk(
    member,
    score,
    reasons,
    source
):

    guild = member.guild

    config = get_server_config(
        guild.id
    )

    if not config:
        return

    monitor_threshold = config["monitor_threshold"]
    alert_threshold = config["alert_threshold"]
    ban_threshold = config["ban_threshold"]

    # LOW RISK
    if score < monitor_threshold:
        return

    # MONITOR
    if score < alert_threshold:

        embed = discord.Embed(
            title="🟡 Suspicious User",
            color=discord.Color.gold(),
            timestamp=datetime.datetime.now(
                datetime.timezone.utc
            )
        )

        embed.add_field(
            name="User",
            value=f"{member} | {member.id}",
            inline=False
        )

        embed.add_field(
            name="Risk Score",
            value=str(score),
            inline=True
        )

        embed.add_field(
            name="Action",
            value="Monitoring",
            inline=True
        )

        embed.add_field(
            name="Source",
            value=source,
            inline=True
        )

        embed.add_field(
            name="Reasons",
            value=(
                "\n".join(reasons)
                if reasons
                else "No details"
            ),
            inline=False
        )

        # Monitor events go ONLY to private logs
        await send_security_log(
            guild,
            embed
        )

        return

    # HIGH RISK / ADMIN ALERT
    if score < ban_threshold:

        increment_alerts(
            guild.id
        )

        embed = discord.Embed(
            title="🟠 HIGH RISK USER",
            color=discord.Color.orange(),
            timestamp=datetime.datetime.now(
                datetime.timezone.utc
            )
        )

        embed.add_field(
            name="User",
            value=f"{member} | {member.id}",
            inline=False
        )

        embed.add_field(
            name="Risk Score",
            value=str(score),
            inline=True
        )

        embed.add_field(
            name="Action",
            value="Admin Alert",
            inline=True
        )

        embed.add_field(
            name="Source",
            value=source,
            inline=True
        )

        embed.add_field(
            name="Reasons",
            value=(
                "\n".join(reasons)
                if reasons
                else "No details"
            ),
            inline=False
        )

        embed.set_thumbnail(
            url=member.display_avatar.url
        )

        # Save complete event to private logs
        await send_security_log(
            guild,
            embed
        )

        # Send important alert to private alert channel
        await send_security_alert(
            guild,
            embed
        )

        return

    # BAN
    try:

        await member.ban(
            reason=(
                f"Scam Protector risk score "
                f"{score}"
            )
        )

        increment_banned(
            guild.id
        )

        embed = discord.Embed(
            title="🚨 SCAM ACCOUNT BANNED",
            color=discord.Color.red(),
            timestamp=datetime.datetime.now(
                datetime.timezone.utc
            )
        )

        embed.add_field(
            name="User",
            value=f"{member} | {member.id}",
            inline=False
        )

        embed.add_field(
            name="Risk Score",
            value=str(score),
            inline=True
        )

        embed.add_field(
            name="Action",
            value="AUTO-BANNED",
            inline=True
        )

        embed.add_field(
            name="Source",
            value=source,
            inline=True
        )

        embed.add_field(
            name="Reasons",
            value=(
                "\n".join(reasons)
                if reasons
                else "No details"
            ),
            inline=False
        )

        embed.set_thumbnail(
            url=member.display_avatar.url
        )

        # Record the ban in private logs
        await send_security_log(
            guild,
            embed
        )

        # Also send the ban as an urgent private alert
        await send_security_alert(
            guild,
            embed
        )

    except discord.Forbidden:

        print(
            f"❌ Cannot ban {member} "
            f"in {guild.name}"
        )

        embed = discord.Embed(
            title="⚠️ BAN FAILED",
            color=discord.Color.orange(),
            timestamp=datetime.datetime.now(
                datetime.timezone.utc
            )
        )

        embed.add_field(
            name="User",
            value=f"{member} | {member.id}",
            inline=False
        )

        embed.add_field(
            name="Risk Score",
            value=str(score),
            inline=True
        )

        embed.add_field(
            name="Reason",
            value=(
                "Bot lacks Ban Members permission "
                "or its role is too low."
            ),
            inline=False
        )

        # Log the failure
        await send_security_log(
            guild,
            embed
        )

        # Alert administrators
        await send_security_alert(
            guild,
            embed
        )

    except discord.HTTPException as e:

        print(
            f"❌ Discord error banning {member}: {e}"
        )

# BOT READY
@bot.event
async def on_ready():

    print(
        f"✅ {bot.user} is online!"
    )

    print(
        f"Protecting {len(bot.guilds)} servers."
    )

    try:

        synced = await bot.tree.sync()

        print(
            f"Synced {len(synced)} commands."
        )

    except Exception as e:

        print(
            f"Command sync error: {e}"
        )

# MEMBER JOIN
@bot.event
async def on_member_join(member):

    config = get_server_config(
        member.guild.id
    )

    # Server hasn't been configured.
    if not config:

        print(
            f"⚠️ {member.guild.name} "
            f"has not been configured."
        )

        return


    minimum_age = config[
        "min_account_age"
    ]

    # RISK SCAN
    score, reasons = initial_scan(
        member,
        minimum_age
    )


    stored_score = add_user_score(
        member.guild.id,
        member.id,
        score
    )


    print(
        f"[JOIN] {member} "
        f"Score: {stored_score}"
    )

    # PUBLIC NEW MEMBER NOTIFICATION
    public_embed = discord.Embed(
        title="👋 New Member Joined",
        color=discord.Color.green(),
        timestamp=datetime.datetime.now(
            datetime.timezone.utc
        )
    )

    public_embed.add_field(
        name="Member",
        value=member.mention,
        inline=True
    )

    public_embed.add_field(
        name="Account Age",
        value=f"{get_account_age(member).days} days",
        inline=True
    )

    public_embed.add_field(
        name="Risk Score",
        value=str(stored_score),
        inline=True
    )

    public_embed.set_thumbnail(
        url=member.display_avatar.url
    )


    await send_general_notification(
        member.guild,
        public_embed
    )

    # SECURITY PROCESSING
    await process_risk(
        member,
        stored_score,
        reasons,
        "New Member Scan"
    )

# MESSAGE MONITOR
@bot.event
async def on_message(message):

    if message.author.bot:
        return

    if not message.guild:

        await bot.process_commands(
            message
        )

        return


    config = get_server_config(
        message.guild.id
    )

    if not config:

        await bot.process_commands(
            message
        )

        return


    points, reasons = message_score(
        message
    )


    if points > 0:

        total_score = add_user_score(
            message.guild.id,
            message.author.id,
            points
        )


        print(
            f"[ACTIVITY] "
            f"{message.author} "
            f"Score: {total_score}"
        )


        await process_risk(
            message.author,
            total_score,
            reasons,
            "Message Activity"
        )


    await bot.process_commands(
        message
    )

# /SETUP
@bot.tree.command(
    name="setup",
    description="Configure Scam Protector for this server"
)
@app_commands.checks.has_permissions(
    manage_guild=True
)
@app_commands.describe(
    general_channel="Channel for public new-member notifications",
    min_account_age="Minimum account age in days",
    monitor_threshold="Risk score for monitoring",
    alert_threshold="Risk score for admin alerts",
    ban_threshold="Risk score for automatic bans"
)
async def setup(
    interaction: discord.Interaction,
    general_channel: discord.TextChannel,
    min_account_age: int = 7,
    monitor_threshold: int = 30,
    alert_threshold: int = 60,
    ban_threshold: int = 80
):

    # SERVER CHECK
    if interaction.guild is None:

        await interaction.response.send_message(
            "❌ This command can only be used inside a server.",
            ephemeral=True
        )

        return

    guild = interaction.guild

    # VALIDATE SETTINGS
    if min_account_age < 0:

        await interaction.response.send_message(
            "❌ Minimum account age cannot be negative.",
            ephemeral=True
        )

        return

    if not (
        monitor_threshold
        < alert_threshold
        < ban_threshold
    ):

        await interaction.response.send_message(
            "❌ Thresholds must be ordered like:\n\n"
            "Monitor < Alert < Ban\n\n"
            "Example: 30 / 60 / 80",
            ephemeral=True
        )

        return

    # BOT PERMISSION CHECK
    bot_member = guild.me

    if bot_member is None:

        await interaction.response.send_message(
            "❌ I could not determine my server permissions.",
            ephemeral=True
        )

        return

    permissions = guild.me.guild_permissions

    if not permissions.manage_channels:

        await interaction.response.send_message(
            "❌ I need **Manage Channels** permission "
            "to create the security channels.",
            ephemeral=True
        )

        return

    # PRIVATE CHANNEL PERMISSIONS
    overwrites = {

        guild.default_role: discord.PermissionOverwrite(
            view_channel=False
        ),

        bot_member: discord.PermissionOverwrite(
            view_channel=True,
            send_messages=True,
            read_message_history=True,
            embed_links=True,
            attach_files=True
        )
    }

    # FIND OR CREATE #scam-logs
    log_channel = discord.utils.get(
        guild.text_channels,
        name="scam-logs"
    )

    if log_channel is None:

        try:

            log_channel = await guild.create_text_channel(
                name="scam-logs",
                overwrites=overwrites,
                reason="Scam Protector private security logs"
            )

        except discord.Forbidden:

            await interaction.response.send_message(
                "❌ I don't have permission to create "
                "`#scam-logs`.",
                ephemeral=True
            )

            return

        except discord.HTTPException as e:

            print(
                f"Error creating scam-logs: {e}"
            )

            await interaction.response.send_message(
                "❌ Discord failed to create `#scam-logs`.",
                ephemeral=True
            )

            return

    else:

        # Make sure an existing channel is private
        try:

            await log_channel.set_permissions(
                guild.default_role,
                view_channel=False,
                reason="Scam Protector private security logs"
            )

            await log_channel.set_permissions(
                bot_member,
                view_channel=True,
                send_messages=True,
                read_message_history=True,
                embed_links=True,
                attach_files=True,
                reason="Scam Protector bot permissions"
            )

        except discord.Forbidden:

            await interaction.response.send_message(
                "❌ I cannot configure permissions for "
                "`#scam-logs`.",
                ephemeral=True
            )

            return

    # FIND OR CREATE #security-alerts
    alert_channel = discord.utils.get(
        guild.text_channels,
        name="security-alerts"
    )

    if alert_channel is None:

        try:

            alert_channel = await guild.create_text_channel(
                name="security-alerts",
                overwrites=overwrites,
                reason="Scam Protector private security alerts"
            )

        except discord.Forbidden:

            await interaction.response.send_message(
                "❌ I don't have permission to create "
                "`#security-alerts`.",
                ephemeral=True
            )

            return

        except discord.HTTPException as e:

            print(
                f"Error creating security-alerts: {e}"
            )

            await interaction.response.send_message(
                "❌ Discord failed to create "
                "`#security-alerts`.",
                ephemeral=True
            )

            return

    else:

        # Make sure an existing channel is private
        try:

            await alert_channel.set_permissions(
                guild.default_role,
                view_channel=False,
                reason="Scam Protector private security alerts"
            )

            await alert_channel.set_permissions(
                bot_member,
                view_channel=True,
                send_messages=True,
                read_message_history=True,
                embed_links=True,
                attach_files=True,
                reason="Scam Protector bot permissions"
            )

        except discord.Forbidden:

            await interaction.response.send_message(
                "❌ I cannot configure permissions for "
                "`#security-alerts`.",
                ephemeral=True
            )

            return

    # SAVE CONFIGURATION
    save_server_config(
        guild_id=guild.id,
        log_channel_id=log_channel.id,
        alert_channel_id=alert_channel.id,
        general_channel_id=general_channel.id,
        min_account_age=min_account_age,
        monitor_threshold=monitor_threshold,
        alert_threshold=alert_threshold,
        ban_threshold=ban_threshold
    )

    # CONFIRMATION
    embed = discord.Embed(
        title="🛡️ Scam Protector Configured",
        description=(
            "This server is now protected."
        ),
        color=discord.Color.green()
    )

    embed.add_field(
        name="📢 General Notifications",
        value=general_channel.mention,
        inline=False
    )

    embed.add_field(
        name="🔒 Private Security Logs",
        value=log_channel.mention,
        inline=False
    )

    embed.add_field(
        name="🚨 Private Security Alerts",
        value=alert_channel.mention,
        inline=False
    )

    embed.add_field(
        name="👤 Minimum Account Age",
        value=f"{min_account_age} days",
        inline=True
    )

    embed.add_field(
        name="🟡 Monitor",
        value=str(monitor_threshold),
        inline=True
    )

    embed.add_field(
        name="🟠 Alert",
        value=str(alert_threshold),
        inline=True
    )

    embed.add_field(
        name="🔴 Ban",
        value=str(ban_threshold),
        inline=True
    )

    await interaction.response.send_message(
        embed=embed,
        ephemeral=True
    )

# /CHECK
@bot.tree.command(
    name="check",
    description="Check the risk profile of a server member"
)
@app_commands.describe(
    user="The member you want to check"
)
async def check(
    interaction: discord.Interaction,
    user: discord.Member
):

    # 1. Check that we're inside a server
    if interaction.guild is None:
        await interaction.response.send_message(
            "❌ This command can only be used inside a server.",
            ephemeral=True
        )
        return

    # 2. Now it is safe to use interaction.guild.id
    settings = get_server_config(
        interaction.guild.id
    )

    # 3. Check whether the server is configured
    if not settings:
        await interaction.response.send_message(
            "⚠️ This server has not been configured.\n"
            "Use `/setup` first.",
            ephemeral=True
        )
        return

    # 4. Continue with the rest of /check...

    age = get_account_age(
        user
    )

    score = get_user_score(
        interaction.guild.id,
        user.id
    )


    current_scan, reasons = initial_scan(
        user,
        settings["min_account_age"]
    )


    total_estimated_score = max(
        score,
        current_scan
    )


    if total_estimated_score >= settings["ban_threshold"]:

        result = "🚨 HIGH RISK"

        result_color = discord.Color.red()

    elif total_estimated_score >= settings["alert_threshold"]:

        result = "🟠 SUSPICIOUS"

        result_color = discord.Color.orange()

    elif total_estimated_score >= settings["monitor_threshold"]:

        result = "🟡 MONITOR"

        result_color = discord.Color.gold()

    else:

        result = "🟢 LOW RISK"

        result_color = discord.Color.green()


    embed = discord.Embed(
        title=f"🔎 Security Check: {user}",
        color=result_color
    )

    embed.add_field(
        name="Account Created",
        value=(
            f"<t:{int(user.created_at.timestamp())}:F>\n"
            f"<t:{int(user.created_at.timestamp())}:R>"
        ),
        inline=False
    )

    embed.add_field(
        name="Account Age",
        value=f"{age.days} days",
        inline=True
    )

    embed.add_field(
        name="Stored Risk Score",
        value=str(score),
        inline=True
    )

    embed.add_field(
        name="Current Risk",
        value=str(total_estimated_score),
        inline=True
    )

    embed.add_field(
        name="Result",
        value=result,
        inline=False
    )

    embed.add_field(
        name="Current Signals",
        value="\n".join(reasons)
        if reasons
        else "No current risk signals detected.",
        inline=False
    )

    embed.set_thumbnail(
        url=user.display_avatar.url
    )


    await interaction.response.send_message(
        embed=embed
    )

# /CONFIG
@bot.tree.command(
    name="config",
    description="View Scam Protector configuration"
)
async def config(
    interaction: discord.Interaction
):

    # Make sure the command is being used inside a server
    if interaction.guild is None:
        await interaction.response.send_message(
            "❌ This command can only be used inside a server.",
            ephemeral=True
        )
        return

    # Get this server's configuration
    settings = get_server_config(
        interaction.guild.id
    )

    if not settings:
        await interaction.response.send_message(
            "⚠️ This server has not been configured.\n"
            "Use `/setup` first.",
            ephemeral=True
        )
        return

    # Get configured channels
    general_channel = interaction.guild.get_channel(
        settings["general_channel_id"]
    )

    log_channel = interaction.guild.get_channel(
        settings["log_channel_id"]
    )

    alert_channel = interaction.guild.get_channel(
        settings["alert_channel_id"]
    )

    # Display configuration
    embed = discord.Embed(
        title="🛡️ Scam Protector Configuration",
        description=(
            "Current security configuration for this server."
        ),
        color=discord.Color.blue()
    )

    embed.add_field(
        name="📢 General Channel",
        value=(
            general_channel.mention
            if general_channel
            else "❌ Channel not found"
        ),
        inline=False
    )

    embed.add_field(
        name="🔒 Security Logs",
        value=(
            log_channel.mention
            if log_channel
            else "❌ Channel not found"
        ),
        inline=False
    )

    embed.add_field(
        name="🚨 Security Alerts",
        value=(
            alert_channel.mention
            if alert_channel
            else "❌ Channel not found"
        ),
        inline=False
    )

    embed.add_field(
        name="👤 Minimum Account Age",
        value=f"{settings['min_account_age']} days",
        inline=True
    )

    embed.add_field(
        name="🟡 Monitor Threshold",
        value=str(settings["monitor_threshold"]),
        inline=True
    )

    embed.add_field(
        name="🟠 Alert Threshold",
        value=str(settings["alert_threshold"]),
        inline=True
    )

    embed.add_field(
        name="🔴 Ban Threshold",
        value=str(settings["ban_threshold"]),
        inline=True
    )

    embed.add_field(
        name="🟢 Status",
        value="Online & Active",
        inline=True
    )

    await interaction.response.send_message(
        embed=embed,
        ephemeral=True
    )

# /STATS
@bot.tree.command(
    name="stats",
    description="Show Scam Protector statistics"
)
async def stats(
    interaction: discord.Interaction
):

    # Make sure the command is being used inside a server
    if interaction.guild is None:
        await interaction.response.send_message(
            "❌ This command can only be used inside a server.",
            ephemeral=True
        )
        return

    settings = get_server_config(
        interaction.guild.id
    )

    if not settings:
        await interaction.response.send_message(
            "⚠️ This server has not been configured.\n"
            "Use `/setup` first.",
            ephemeral=True
        )
        return

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM user_risk
        WHERE guild_id = ?
        """,
        (interaction.guild.id,)
    )

    monitored_users = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT banned, alerts
        FROM statistics
        WHERE guild_id = ?
        """,
        (interaction.guild.id,)
    )

    statistics = cursor.fetchone()

    conn.close()

    embed = discord.Embed(
        title="🛡️ Scam Protector Stats",
        color=discord.Color.blue()
    )

    embed.add_field(
        name="Server",
        value=interaction.guild.name,
        inline=False
    )

    embed.add_field(
        name="Users Monitored",
        value=str(monitored_users),
        inline=True
    )

    embed.add_field(
        name="Accounts Banned",
        value=str(statistics["banned"]),
        inline=True
    )

    embed.add_field(
        name="Security Alerts",
        value=str(statistics["alerts"]),
        inline=True
    )

    embed.add_field(
        name="Monitor Threshold",
        value=str(settings["monitor_threshold"]),
        inline=True
    )

    embed.add_field(
        name="Alert Threshold",
        value=str(settings["alert_threshold"]),
        inline=True
    )

    embed.add_field(
        name="Ban Threshold",
        value=str(settings["ban_threshold"]),
        inline=True
    )

    embed.add_field(
        name="Status",
        value="🟢 Online & Active",
        inline=True
    )

    await interaction.response.send_message(
        embed=embed
    )

# SETUP ERROR HANDLER
@setup.error
async def setup_error(
    interaction: discord.Interaction,
    error
):

    if isinstance(
        error,
        app_commands.errors.MissingPermissions
    ):

        await interaction.response.send_message(
            "❌ You need **Manage Server** permission "
            "to configure Scam Protector.",
            ephemeral=True
        )

    else:

        print(
            f"/setup error: {error}"
        )

        if not interaction.response.is_done():

            await interaction.response.send_message(
                "❌ An error occurred while configuring "
                "Scam Protector.",
                ephemeral=True
            )

# START BOT
def main():
    if not TOKEN:
        raise RuntimeError("DISCORD_TOKEN is not set")

    bot.run(TOKEN)


if __name__ == "__main__":
    main()