#!/usr/bin/env python3
"""Take screenshots of the MANTIS dashboard using Playwright."""

import asyncio
from playwright.async_api import async_playwright

DASHBOARD = "http://127.0.0.1:8843"
OUT = "screenshots"


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page(viewport={"width": 1440, "height": 900})

        # 1. Overview / main dashboard
        await page.goto(DASHBOARD, wait_until="networkidle")
        await asyncio.sleep(3)
        await page.screenshot(path=f"{OUT}/01_overview.png", full_page=False)
        print("[+] 01_overview.png")

        # 2. Events tab - wait for table to populate
        await page.click('button:has-text("Events")')
        await asyncio.sleep(3)
        await page.screenshot(path=f"{OUT}/02_events.png", full_page=False)
        print("[+] 02_events.png")

        # 3. Sessions tab
        await page.click('button:has-text("Sessions")')
        await asyncio.sleep(2)
        await page.screenshot(path=f"{OUT}/03_sessions.png", full_page=False)
        print("[+] 03_sessions.png")

        # 4. Alerts tab
        await page.click('button:has-text("Alerts")')
        await asyncio.sleep(2)
        await page.screenshot(path=f"{OUT}/04_alerts.png", full_page=False)
        print("[+] 04_alerts.png")

        # 5. Database tab
        await page.click('button:has-text("Database")')
        await asyncio.sleep(2)
        await page.screenshot(path=f"{OUT}/05_database.png", full_page=False)
        print("[+] 05_database.png")

        # 6. Map tab
        await page.click('button:has-text("Map")')
        await asyncio.sleep(2)
        await page.screenshot(path=f"{OUT}/06_map.png", full_page=False)
        print("[+] 06_map.png")

        # 7. Config tab
        await page.click('button:has-text("Config")')
        await asyncio.sleep(2)
        await page.screenshot(path=f"{OUT}/07_config.png", full_page=False)
        print("[+] 07_config.png")

        # 8. Full page overview scroll
        await page.click('button:has-text("Overview")')
        await asyncio.sleep(2)
        await page.screenshot(path=f"{OUT}/08_overview_full.png", full_page=True)
        print("[+] 08_overview_full.png")

        await browser.close()
        print("\nDone! Screenshots saved to screenshots/")


asyncio.run(main())
