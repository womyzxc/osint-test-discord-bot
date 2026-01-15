import discord
from discord.ext import commands
import discord.app_commands
import aiohttp
import asyncio
import os
import re
import json
from datetime import datetime
from typing import Optional, Dict, List
import logging

# Railway logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

class FullOSINTBot(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.session = None
        self.tree = bot.tree

    async def cog_load(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        logger.info("🔥 OSINT Session Ready")

    async def cog_unload(self):
        if self.session:
            await self.session.close()

    def detect_target_type(self, target: str) -> str:
        target = target.strip().lower()
        
        # Phone
        phone_match = re.match(r'^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$', target.replace(' ', ''))
        if phone_match:
            return "phone"
        
        # Email
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
            return "email"
            
        # IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            return "ip"
            
        # Domain
        if re.match(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-zA-Z]{2,}$', target):
            return "domain"
            
        return "person"

    @discord.app_commands.command(name="osint", description="🔍 FULL OSINT - Auto detects Phone/Email/IP/Domain/Person")
    async def osint(self, interaction: discord.Interaction, target: str, modules: Optional[str] = "all"):
        await interaction.response.defer()
        
        target_type = self.detect_target_type(target)
        modules_list = [m.strip() for m in modules.lower().split(',')] if modules != "all" else ['all']
        
        embed = discord.Embed(
            title=f"🕵️ OSINT Recon: {target}",
            description=f"**Type:** `{target_type.upper()}` | **Modules:** {modules}",
            color=0x00ff88
        )
        
        # Run OSINT modules
        results = {}
        
        if target_type == "phone" or 'phone' in modules_list or 'all' in modules_list:
            results["phone"] = await self.phone_osint(target)
            
        if target_type == "email" or 'email' in modules_list or 'all' in modules_list:
            results["email"] = await self.email_osint(target)
            
        if target_type == "ip" or 'ip' in modules_list or 'all' in modules_list:
            results["ip"] = await self.ip_osint(target)
            
        if target_type == "domain" or 'domain' in modules_list or 'all' in modules_list:
            results["domain"] = await self.domain_osint(target)
            
        if target_type == "person" or 'people' in modules_list or 'all' in modules_list:
            results["person"] = await self.people_osint(target)
        
        # Add results to embed
        for key, data in results.items():
            embed.add_field(
                name=f"{self.get_emoji(key)} {key.upper()} OSINT",
                value=f"```{json.dumps(data, indent=2, default=str)[:1000]}```",
                inline=False
            )
        
        embed.set_footer(text="🔥 100% FREE APIs | Railway Hosted")
        embed.timestamp = datetime.utcnow()
        await interaction.followup.send(embed=embed)

    # 📱 PHONE OSINT
    async def phone_osint(self, phone: str) -> Dict:
        results = {"raw": phone, "formatted": self.format_phone(phone)}
        
        try:
            clean_phone = re.sub(r'[^\d+]', '', phone)
            url = f"http://apilayer.net/api/validate?access_key=&number={clean_phone}&format=1"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results.update({
                        "carrier": data.get("carrier"),
                        "type": data.get("line_type"), 
                        "location": data.get("location"),
                        "valid": data.get("valid", False),
                        "country": data.get("country_name")
                    })
        except Exception as e:
            results["note"] = "Numverify unavailable"
        
        return results

    def format_phone(self, phone: str) -> str:
        digits = re.sub(r'[^\d]', '', phone)
        if len(digits) == 10:
            return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
        elif len(digits) == 11 and digits.startswith('1'):
            return f"+1 ({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
        return phone

    # ✉️ EMAIL OSINT
    async def email_osint(self, email: str) -> Dict:
        domain = email.split('@')[1]
        results = {"email": email, "domain": domain}
        
        dns = await self.dns_recon(domain)
        results["dns"] = {k: dns[k][0] if dns[k] else "None" for k in dns}
        
        names = ['info', 'support', 'admin', 'contact']
        results["patterns"] = [f"{name}@{domain}" for name in names]
        
        return results

    # 🌐 IP OSINT
    async def ip_osint(self, ip: str) -> Dict:
        try:
            async with self.session.get(f"https://ipapi.co/{ip}/json/") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        "city": data.get("city"),
                        "region": data.get("region"), 
                        "country": data.get("country_name"),
                        "org": data.get("org"),
                        "lat": data.get("latitude"),
                        "lon": data.get("longitude")
                    }
        except:
            pass
        return {"error": "IP lookup failed"}

    # 🏠 DOMAIN OSINT
    async def domain_osint(self, domain: str) -> Dict:
        try:
            dns, whois, subs = await asyncio.gather(
                self.dns_recon(domain),
                self.whois_free(domain),
                self.subdomain_enum_free(domain)
            )
            return {
                "dns": {k: dns[k][0] if dns[k] else "None" for k in dns},
                "whois": whois,
                "subdomains": subs[:5]
            }
        except:
            return {"error": "Domain lookup failed"}

    # 👥 PEOPLE OSINT
    async def people_osint(self, name: str) -> Dict:
        username = re.sub(r'[^\w]', '', name.lower())
        return {
            "name": name,
            "username": username,
            "profiles": {
                "twitter": f"https://twitter.com/{username}",
                "github": f"https://github.com/{username}",
                "linkedin": f"https://linkedin.com/in/{username}"
            }
        }

    # 🔧 SUPPORT APIs
    async def dns_recon(self, domain: str) -> Dict:
        dns = {}
        types = ['A', 'MX', 'NS']
        for t in types:
            try:
                async with self.session.get(f"https://dns.google/resolve?name={domain}&type={t}") as r:
                    data = await r.json()
                    dns[t] = [ans.get('data') for ans in data.get('Answer', [])]
            except:
                dns[t] = []
        return dns

    async def whois_free(self, domain: str) -> Dict:
        try:
            async with self.session.get(f"https://whoisjson.com/v1/{domain}") as r:
                return await r.json() if r.status == 200 else {}
        except:
            return {}

    async def subdomain_enum_free(self, domain: str) -> List[str]:
        try:
            async with self.session.get(f"https://crt.sh/?q=%25.{domain}&output=json") as r:
                data = await r.json()
                subs = set()
                for e in data[:20]:
                    for line in str(e.get('name_value', '')).split('\n'):
                        clean = line.strip().strip('*.')
                        if domain in clean: subs.add(clean)
                return list(subs)
        except:
            return []

    def get_emoji(self, key: str) -> str:
        emojis = {
            "phone": "📱", "email": "✉️", "ip": "🌐", 
            "domain": "🏠", "person": "👥"
        }
        return emojis.get(key, "🔍")

# 🛠️ QUICK COMMANDS (Traditional prefix)
@bot.command(name='phone')
async def phone_cmd(ctx, *, phone: str):
    await ctx.defer()
    cog = bot.get_cog('FullOSINTBot')
    result = await cog.phone_osint(phone)
    embed = discord.Embed(title="📱 Phone OSINT", color=0xff6600)
    embed.description = f"```{json.dumps(result, indent=2, default=str)[:1900]}```"
    await ctx.followup.send(embed=embed)

@bot.command(name='ip')
async def ip_cmd(ctx, ip: str):
    await ctx.defer()
    cog = bot.get_cog('FullOSINTBot')
    result = await cog.ip_osint(ip)
    embed = discord.Embed(title="🌐 IP OSINT", color=0x0099ff)
    embed.description = f"```{json.dumps(result, indent=2, default=str)[:1900]}```"
    await ctx.followup.send(embed=embed)

@bot.event
async def on_ready():
    logger.info(f"✅ {bot.user} is online!")
    await bot.add_cog(FullOSINTBot(bot))
    
    try:
        synced = await bot.tree.sync()
        logger.info(f"✅ Synced {len(synced)} slash commands")
    except Exception as e:
        logger.error(f"❌ Slash sync failed: {e}")

if __name__ == "__main__":
    token = os.getenv('DISCORD_TOKEN')
    if token:
        bot.run(token)
    else:
        logger.error("❌ DISCORD_TOKEN not set!")
