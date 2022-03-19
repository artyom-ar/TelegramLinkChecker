import logging
import os
import re
import requests
from aiogram import Bot, Dispatcher, executor, types
import time
from datetime import datetime
import asyncio
from aiorequest.sessions import Session, HttpSession
from aiorequest.responses import Response
from aiorequest.urls import HttpUrl

# VirusTotal API key
API_KEY = os.getenv("API_KEY", None)

# Telegram Bot token
TOKEN = os.getenv("TOKEN", None)

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logging.basicConfig(filename="example.log", encoding="utf-8", level=logging.DEBUG)
logger = logging.getLogger(__name__)

bot = Bot(token=TOKEN)
dp = Dispatcher(bot)


async def process_msg(result, url, message: types.Message):
    user = message.from_user.full_name
    cur_time = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    if result == "clean":
        print("a")
        print(TOKEN)
        return
    if result == "suspicious":
        await message.answer(text=f"URL sent {user} is {result}, don't enter the link!")
        await message.answer(
            text=f"{user} banned for sending potentially malicious links!"
        )
        await message.delete()
        await bot.kick_chat_member(
            chat_id=message.chat.id,
            user_id=message.from_user.id,
            until_date=time.time() + 86400,
        )
        logger.info(f"malicious link: {url} sent by: {user} in {cur_time}")
        return

    logger.info(f"unexpected behavior in the link: {url} sent by: {user} in {cur_time}")


def request_virustotal_analysis(url):
    headers = {"x-apikey": API_KEY}
    payload = {
        "url": url,
    }
    r = requests.post(
        f"https://www.virustotal.com/api/v3/urls",
        data=payload,
        headers=headers,
    )
    analysis_id = r.json().get("data").get("id")
    return analysis_id


async def get_analysis(analysis_id):
    headers = {"x-apikey": API_KEY}
    session: Session
    report = {}
    while not report:
        async with HttpSession() as session:
            response: Response = await session.get(
                HttpUrl(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"),
                headers=headers,
            )
        status, response = await response.status(), await response.as_json()
        report = response.get("data").get("attributes").get("results")
        await asyncio.sleep(0.1)
    return status, response


async def summarize_scan_result(analysis):
    report = analysis.get("attributes").get("results")
    result = "clean"
    acceptable_results = set(["clean", "none", "unrated"])
    # aggregate all of the VirusTotal partners, if atleast one of them says the link is suspicious - it is!
    for key, val in report.items():
        if key != "stats" or key != "status":
            res = val.get("result")
            if res not in acceptable_results:
                result = "suspicious"
    return result


@dp.message_handler(regexp='https?://[^\s<>"]+|www\.[^\s<>"]+')
async def process_urls(message: types.Message) -> None:
    # extract URLs, can be more than one!
    url_list = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', message.text)

    for url in url_list:
        analysis_id = request_virustotal_analysis(url)
        analysis = await get_analysis(analysis_id)
        result = await summarize_scan_result(analysis[1].get("data"))
        await process_msg(result, url, message)


if __name__ == "__main__":
    executor.start_polling(dp, skip_updates=True)
