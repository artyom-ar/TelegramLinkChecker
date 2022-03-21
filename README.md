# TelegramLinkChecker

A bot that checks for malicious links sent in the group he's in.

How to run

- Install dependencies with Pipenv
- Add VirusTotal api key and Telegram bot token to a `.env` file using the dev.env format
- Add the bot to a group and give it message deletion and member kicking permissions
- Run the script using `pipenv run python3 async_telegram_bot.py`
