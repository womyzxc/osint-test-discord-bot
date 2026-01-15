import discord
from discord.ext import commands
import aiohttp
import asyncio
import os
import re
import json
from datetime import datetime
from typing import Optional, List, Dict
import logging

# Railway logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

class FullOSINTBot(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.session = None
        
        # Regex patterns
        self.phone_pattern = re.compile(r'^\+?1?[-.\s]?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})$')
        self.email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        self.ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

    async def cog_load(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=12),
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        logger.info("🔥 Full OSINT session ready!")

    async def cog_unload(self):
        if self.session:
            await self.session.close()

    # 🎯 MAIN ALL-IN-ONE OSINT COMMAND
    @commands.slash_command(name="osint", description="🔍 FULL OSINT - Auto detects Phone/Email/IP/Domain/Person")
    async def osint(self, ctx, target: str, modules: Optional[str] = "all"):
        """Complete OSINT reconnaissance - Auto detects input type!"""
        await ctx.defer()
        
        # Detect target type
        target_type = self.detect_target_type(target)
        clean_target = self.clean_target(target)
        
        modules_list = [m.strip().lower() for m in modules.split(',')] if modules else ['all']
        if 'all' in modules_list:
            modules_list = ['basic', 'phone', 'email', 'ip', 'domain', 'people']
        
        results = {
            "target": clean_target,
            "detected_type": target_type,
            "scan_time": datetime.utcnow().isoformat()
        }
        
        # Dynamic task creation based on target type
        tasks = []
        for module in modules_list:
            task = self.get_osint_module(module, clean_target, target_type)
            if task:
                tasks.append(task)
        
        # Execute all tasks concurrently
        if tasks:
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(task_results):
                if isinstance(result, dict):
                    results.update(result)
        
        embed = self.create_osint_embed(results)
        await ctx.followup.send(embed=embed)

    def detect_target_type(self, target: str) -> str:
        target = target.strip().lower()
        if self.phone_pattern.match(re.sub(r'[^\d+]', '', target)):
            return "phone"
        if self.email_pattern.match(target):
            return "email"
        if self.ip_pattern.match(target):
            return "ip"
        if re.match(r'^([a-z0-9-]+\.)+[a-z]{2,}$', target):
            return "domain"
        return "person"

    def clean_target(self, target: str) -> str:
        return re.sub(r'^https?://|www\.', '', target).split('/')[0].strip()

    def get_osint_module(self, module: str, target: str, target_type: str):
        methods = {
            'phone': self.phone_osint,
            'email': self.email_osint,
            'ip': self.ip_osint,
            'domain': self.domain_osint,
            'people': self.people_osint,
            'basic': lambda t: self.basic_osint(t)
        }
        return methods.get(module, None)(target) if module in methods else None

    # 📱 PHONE OSINT (Numverify + Patterns - FREE)
    async def phone_osint(self, phone: str) -> Dict:
        """FREE Phone number OSINT"""
        results = {'phone': phone, 'formatted': self.format_phone(phone)}
        
        # Numverify free lookup
        try:
            clean_phone = re.sub(r'[^\d+]', '', phone)
            url = f"http://apilayer.net/api/validate?access_key=&number={clean_phone}&format=1"
            async with self.session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    results.update({
                        'carrier': data.get('carrier', 'Unknown'),
                        'type': data.get('line_type', 'Unknown'),
                        'location': data.get('location', 'Unknown'),
                        'valid': data.get('valid', False),
                        'country': data.get('country_name', 'Unknown')
                    })
        except:
            results['note'] = 'Enhanced lookup unavailable - patterns active'
        
        return {'phone_osint': results}

    def format_phone(self, phone: str) -> str:
        """Standardize phone format"""
        digits = re.sub(r'[^\d+]', '', phone)
        if digits.startswith('+'):
            return digits
        if len(digits) == 10:
            return f"+1{digits}"
        return digits

    # ✉️ EMAIL OSINT (Hunter patterns + Domain recon - FREE)
    async def email_osint(self, email: str) -> Dict:
        """FREE Email OSINT with domain recon"""
        domain = email.split('@')[1]
        results = {'email': email, 'domain': domain}
        
        # Domain DNS
        dns = await self.dns_recon(domain)
        results['dns'] = dns
        
        # Email patterns for domain
        patterns = [f"{prefix}@{domain}" for prefix in 
                   ['info', 'support', 'admin', 'contact', 'hello', 'noreply']]
        results['patterns'] = patterns
        
        return {'email_osint': results}

    # 🌐 IP OSINT (ipapi.co - FREE 1000/day)
    async def ip_osint(self, ip: str) -> Dict:
        """FREE IP Geolocation & Owner"""
        try:
            async with self.session.get(f"https://ipapi.co/{ip}/json/") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        'ip_osint': {
                            'ip': ip,
                            'city': data.get('city'),
                            'region': data.get('region'),
                            'country': data.get('country_name'),
                            'org': data.get('org'),
                            'isp': data.get('org'),
                            'lat': data.get('latitude'),
                            'lon': data.get('longitude'),
                            'timezone': data.get('timezone')
                        }
                    }
        except:
            pass
        return {'ip_osint': {'error': 'IP lookup failed'}}

    # 🏠 DOMAIN OSINT (Full stack - FREE)
    async def domain_osint(self, domain: str) -> Dict:
        """Complete FREE domain reconnaissance"""
        tasks = [
            self.dns_recon(domain),
            self.whois_free(domain),
            self.subdomain_enum_free(domain),
            self.tech_stack_free(f"https://{domain}")
        ]
        dns, whois, subs, tech = await asyncio.gather(*tasks)
        return {
            'domain_osint': {
                'dns': dns,
                'whois': whois,
                'subdomains': subs,
                'tech': tech
            }
        }

    # 👥 PEOPLE OSINT (Social + Patterns - FREE)
    async def people_osint(self, name: str) -> Dict:
        """FREE People reconnaissance"""
        username = re.sub(r'\s+', '', name.lower())
        profiles = {
            'twitter': f"https://twitter.com/{username}",
            'github': f"https://github.com/{username}",
            'linkedin': f"https://linkedin.com/in/{username}",
            'instagram': f"https://instagram.com/{username}",
            'facebook': f"https://facebook.com/{username}"
        }
        return {'people_osint': {'name': name, 'profiles': profiles}}

    # 🛠️ SUPPORT FUNCTIONS (FREE APIs)
    async def dns_recon(self, domain: str) -> Dict:
        """Google DNS API - UNLIMITED FREE"""
        records = {}
        types = ['A', 'MX', 'NS', 'TXT']
        for t in types:
            try:
                async with self.session.get(f"https://dns.google/resolve?name={domain}&type={t}") as r:
                    data = await r.json()
                    records[t] = [ans['data'] for ans in data.get('Answer', [])][:2]
            except:
                records[t] = []
        return records

    async def whois_free(self, domain: str) -> Dict:
        """whoisjson.com - 1000/day FREE"""
        try:
            async with self.session.get(f"https://whoisjson.com/v1/{domain}") as r:
                data = await r.json()
                return {
                    'registrar': data.get('registrar'),
                    'created': data.get('created'),
                    'expires': data.get('expires'),
                    'status': data.get('status', [])
                }
        except:
            return {}

    async def subdomain_enum_free(self, domain: str) -> List:
        """crt.sh - UNLIMITED FREE"""
        try:
            async with self.session.get(f"https://crt.sh/?q=%25.{domain}&output=json") as r:
                data = await r.json()
                subs = set()
                for entry in data[:25]:
                    name = entry.get('name_value', '')
                    for line in name.split('\n'):
                        clean = line.strip(' *.')
                        if domain in clean:
                            subs.add(clean)
                return sorted(list(subs))
        except:
            return []

    async def tech_stack_free(self, url: str) -> Dict:
        """HTTP Headers - UNLIMITED FREE"""
        try:
            async with self.session.get(url, allow_redirects=True) as r:
                headers = dict(r.headers)
                server = headers.get('server', 'Unknown')
                techs = []
                if 'nginx' in server.lower(): techs.append('Nginx')
                if 'apache' in server.lower(): techs.append('Apache')
                return {'server': server, 'powered_by': headers.get('x-powered-by'), 'techs': techs}
        except:
            return {}

    async def basic_osint(self, target: str) -> Dict:
        """Basic info for any target"""
        return {'basic': {'length': len(target), 'chars': set(target)}}

    def create_osint_embed(self, results: Dict) -> discord.Embed:
        embed = discord.Embed(
            title=f"🕵️ OSINT Complete - {results['detected_type'].upper()}",
            color=0x00ff88
        )
        
        # Type specific formatting
        if 'phone_osint' in results:
            phone_data = results['phone_osint']
            embed.add_field(
                name="📱 Phone Details",
                value=f"```{json.dumps(phone_data, indent=2)[:1000]}```",
                inline=False
            )
        if 'email_osint' in results:
            email_data = results['email_osint']
            embed.add_field(name="✉️ Email Recon", value=f"Domain: {email_data['domain']}", inline=True)
        if 'ip_osint' in results:
            ip_data = results['ip_osint']
            embed.add_field(
                name="🌐 IP Geolocation",
                value=f"```{ip_data.get('city', 'N/A')}, {ip_data.get('country', 'N/A')} | {ip_data.get('org', 'N/A')}```",
                inline=False
            )
        if 'domain_osint' in results:
            domain_data = results['domain_osint']
            embed.add_field(name="🏠 Domain", value=f"Subdomains: {len(domain_data['subdomains'])}", inline=True)
        
        embed.set_footer(text="🔥 100% FREE APIs | Railway Hosted")
        return embed

# 🛠️ SPECIALIZED COMMANDS
@bot.slash_command(name="phone", description="📱 Phone number OSINT")
async def phone_cmd(ctx, number: str):
    await ctx.defer()
    cog = bot.get_cog('FullOSINTBot')
    result = await cog.phone_osint(number)
    embed = discord.Embed(title="📱 Phone OSINT", color=0xff6600, description=f"```{str(result)}```")
    await ctx.followup.send(embed=embed)

@bot.slash_command(name="email", description="✉️ Email OSINT")
async def email_cmd(ctx, email: str):
    await ctx.defer()
    cog = bot.get_cog('FullOSINTBot')
    result = await cog.email_osint(email)
    embed = discord.Embed(title="✉️ Email OSINT", color=0xff6600, description=f"```{str(result)}```")
    await ctx.followup.send(embed=embed)

@bot.slash_command(name="ip", description="🌐 IP OSINT & Geolocation")
async def ip_cmd(ctx, ip: str):
    await ctx.defer()
    cog = bot.get_cog('FullOSINTBot')
    result = await cog.ip_osint(ip)
    embed = discord.Embed(title="🌐 IP OSINT", color=0xff6600, description=f"```{str(result)}```")
    await ctx.followup.send(embed=embed)

@bot.slash_command(name="detect", description="🔍 Auto-detect target type")
async def detect_cmd(ctx, target: str):
    cog = bot.get_cog('FullOSINTBot')
    target_type = cog.detect_target_type(target)
    embed = discord.Embed(title="🔍 Target Analysis", 
                         description=f"**{target}** → **{target_type.upper()}**", 
                         color=0x0099ff)
    await ctx.respond(embed=embed)

# 🚀 RAILWAY READY STARTUP
@bot.event
async def on_ready():
    logger.info(f"🕵️ {bot.user} is online - Full OSINT ready!")
    try:
        synced = await bot.tree.sync()
        logger.info(f"✅ Synced {len(synced)} OSINT commands")
    except Exception as e:
        logger.error(f"❌ Command sync failed: {e}")

async def main():
    async with bot:
        await bot.add_cog(FullOSINTBot(bot))
        token = os.getenv('DISCORD_TOKEN')
        if not token:
            logger.error("❌ DISCORD_TOKEN not found!")
            return
        await bot.start(token)

if __name__ == "__main__":
    asyncio.run(main())
