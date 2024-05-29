import requests
import os
from datetime import datetime
from markdown import markdown
import time
from bs4 import BeautifulSoup
from datetime import datetime
import re
import json
import argparse

parser = argparse.ArgumentParser(description='دریافت cvename از خط فرمان')
parser.add_argument('--cvename', type=str, default='', help='نام CVE (اگر وجود دارد)')

args = parser.parse_args()

cvename = args.cvename

matched_cves = {}

all_cve = {}


def send_cve_message_to_telegram(cve_data):
    try:
        # Generate message from JSON data
        message = f"<b>Title:</b> {cve_data['title']}<br>"
        message += f"<b>Source:</b> {cve_data['source']}<br>"
        message += f"<b>Link:</b> <a href='{cve_data['link']}'>View Details</a><br>"
        message += f"<b>Summary:</b> {cve_data['summary']}<br>"
        message += f"<b>Publish Date:</b> {cve_data['publish_date']}<br><br>"
        message += f"<b>Info:</b> {cve_data['info']}<br>"
        message += f"<b>Tags:</b> {', '.join(cve_data['tags'])}<br>"

        # Telegram configuration
        # telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        # telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')
        # telegram_thread_id = os.getenv('TELEGRAM_THREAD_ID')

        telegram_bot_token = "6657742129:AAErw-H-hewoR5KHUjuGS769Ovae3vgpJIY"
        telegram_chat_id = -1002029707582
        telegram_thread_id = 18514

        if not telegram_bot_token:
            raise ValueError("TELEGRAM_BOT_TOKEN wasn't configured in the secrets!")
        
        if not telegram_chat_id:
            raise ValueError("TELEGRAM_CHAT_ID wasn't configured in the secrets!")
        
        if not telegram_thread_id:
            raise ValueError("TELEGRAM_THREAD_ID wasn't configured in the secrets!")
        
        # Send message to Telegram
        url = f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage?chat_id={telegram_chat_id}&message_thread_id={telegram_thread_id}&text={message}&message=HTML'

        
        response = requests.get(url)
        
        if response.status_code != 200:
            raise Exception(f"Failed to send message: {response.status_code}")
        else:
            print("Message sent successfully")
        
        resp = response.json()
        if not resp['ok']:
            raise Exception(f"Telegram API error: {resp['description']}")
    
    except Exception as e:
        with open("./logs/logs.txt", "a") as log_file:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_file.write(f"{current_time} - Error on sending message to telegram for CVE {cve_data['title']}: {e}\n")
        raise



def convert_datetime_format(datetime_str):
    dt = datetime.fromisoformat(datetime_str)
    formatted_date = dt.strftime('%Y-%m-%d')
    return formatted_date

def convert_json(all_cve):
    if not os.path.exists('cve_files'):
        os.makedirs('cve_files')
    
    for cve_id, cve_data in all_cve.items():
        file_name = f"cve_files/{cve_id}.json"

        soup = BeautifulSoup(cve_data['info'], features="lxml")
        text = ''.join(soup.find_all(string=True))

        data = {
        'tags': cve_data["tags"],
        'source': "زفتا",
        'title': cve_data["title"],
        'link': "https://nvd.nist.gov/vuln/detail/" + cve_data["CVE"],
        'summary': f"{text[:200]} ... ",
        'info': f"{cve_data['info']}<br> <h2>راهکار امن سازی :</h2><br> {cve_data['remedition']}" ,
        'publish_date': convert_datetime_format(cve_data['publishedDate']),
        'chart': cve_data['chart'],
        }

        print(f"sending {cve_data["CVE"]} to telegram ...")
        send_cve_message_to_telegram(data)

        # Dump the data to JSON with proper indentation and encoding
        json_data = json.dumps(data, ensure_ascii=False, indent=4)
        with open(file_name, 'w', encoding='utf-8') as file:
            file.write(json_data)
        print(f"file {cve_data["CVE"]} created")




def remove_compiled_section(text):
    marker = "### compiled"
    marker_index = text.find(marker)
    if marker_index != -1:
        return text[:marker_index]
    return text


def create_cve_details(cve):
    ai_dic = {}
    attempt = 0
    max_attempts = 3

    while attempt < max_attempts:
        try:
            print(f"[+] Working on: {cve['CVE']}")
            references_string = ', '.join(cve['References'])
            for key, prompt in prompts.items():
                final_prompt = prompt.replace("{{ID}}", cve['CVE']).replace("{{REF}}", references_string)
                print(f"Send prompt to khoj ...")
                res = RAG(final_prompt)
                if "Too Many Requests" in res:
                    raise Exception("Too Many Requests: Please slow down.")
                if key == 'title':  
                    res = remove_compiled_section(markup_to_text(res))
                    match = re.search(r'\[([^\]]+)\]', res).group(1)
                    ai_dic[key] = match
                    print(f"create title for {cve['CVE']}")
                elif key == 'tags':
                    res = remove_compiled_section(markup_to_text(res))
                    tags = re.findall(r'\[([^\]]+)\]', res)
                    ai_dic[key] = tags
                    print(f"create tags for {cve['CVE']}")
                elif key == 'chart':
                    res = remove_compiled_section(markup_to_text(res))
                    numbers = re.findall(r'\[(.*?)\]', res)
                    chart = [int(num) for group in numbers for num in group.split(', ')]
                    ai_dic[key] = chart
                    print(f"create chart for {cve['CVE']}")
                else: 
                    res = remove_compiled_section(markdown(res))
                    ai_dic[key] = res.replace("\n","")
                    print(f"create {key} for {cve['CVE']}")
            break  
        except Exception as e:
            attempt += 1
            print(f"Error occurred: {e}. Retrying {attempt}/{max_attempts}...")
            if attempt == max_attempts:
                print("Max attempts reached. Writing error to logs and exiting the program.")
                with open("./log/logs.txt", "a") as log_file:
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_file.write(f"{current_time} - Error on attempt {attempt} for CVE {cve['CVE']}: {e}\n")
                raise  
    return ai_dic

prompts = {
    "info" : "یک توضیح کامل در مورد آسیب پذیری با شناسه {{ID}} با منابع {{REF}} به زبان فارسی بهم بده و هیچ توضیحی در خصوص راهکار امن سازی نده و در متنی که بهم میدی هم سوال از من نپرس ",
    "remedition" : "یک راهکار امن سازی برای آسیب پذیری با شناسه {{ID}} بهم بده با توجه به منابع {{REF}} و اگر در ورژن های بعدی آسیب پذیری رفع شده بود ورژن امن را در آخر بهم بگو و در متن هم از من سوال نپرس",
    "chart" : "با توجه به به آسیب پذیری با شناسه {{ID}} اگر در مورد دیتابیس بود عدد 17 را بهم نمایش بده اگر در مورد سیستم عامل بود عدد 16 و 17 و 2 و اگر در مورد تجهیزات بود مثل سیسکو ، فورتیگیت ، استوریج و .. عدد 16 و 4 و اگر در مورد سایت وب اپلیکیشن و وب سرور بود 17 و 18 را برایم در خروجی نمایش بده و اینکه حتما اعداد را داخل [] بگذار",
    "title" : "یک عنوان به زبان فارسی برای آسیب پذیری با شناسه {{ID}} بهم بده و آن را داخل [] بنویس با توجه به منابع {{REF}} و در آن نام CVEو دستگاه آسیب پذیر را بنویس",
    "tags" : "چند تا برچسب به انگلیسی برای آسیب پذیری {{ID}} بهم بده در برچسب از نوشتن امتیاز خودداری بکن و فقط برچسب های کلی را بنویس هر هر بچسب را داخل [] بنویس",
}

def getcve_details(cve):
    url = "https://olbat.github.io/nvdcve/" + cve +".json"

    response = requests.get(url)
    data = response.json()
    urls = [ref['url'] for ref in data['cve']['references']['reference_data']]
    return {
        "CVE" : cve,
        "References" : urls,
        "publishedDate" : data['publishedDate']
    }



def markup_to_text(markup_text):
    html = markdown(markup_text)
    soup = BeautifulSoup(html, features="lxml")
    text = ''.join(soup.find_all(string=True))

    return text


def RAG(message=''):
    time.sleep(5)
    attempt = 0
    max_attempts = 3

    while attempt < max_attempts:
        try:
            
            headers = {
                "Pragma": "no-cache",
                "dnt": "1",
                "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                "Cache-Control": "no-cache",
                'Authorization': 'Bearer kk-kv9gUa9Z_JBXsvI4DIFBjWxmQAf-nkwmd7Zdzixj4J8',
                "sec-gpc": "1",
            }

            params = {
                'client': 'web',
                'agent_slug': 'khoj',
            }

            response1 = requests.post('https://app.khoj.dev/api/chat/sessions', params=params, headers=headers)
            conversation_id = ''
            if response1.status_code == 200:
                conversation_id = response1.json()['conversation_id']
                print(f"your conversation_id is : {conversation_id}")

            response = requests.get(
                f'https://app.khoj.dev/api/chat?q=%2Fonline {message}&&n=5&client=web&stream=true&conversation_id={conversation_id}&region=Tehran&city=Tehran&country=Iran&timezone=Asia/Tehran',
                headers=headers,
            )


            response_del = requests.delete('https://app.khoj.dev/api/chat/history?client=web&conversation_id=' + str(conversation_id), headers=headers)
            if response_del.status_code == 200:
                print(f"Conversation {conversation_id} history cleared")

            return response.text

        except Exception as e:
            attempt += 1
            print(f"Error occurred: {e}. Retrying {attempt}/{max_attempts}...")
            if attempt == max_attempts:
                print("Max attempts reached. Writing error to logs and exiting the program.")
                with open("./log/logs.txt", "a") as log_file:
                    log_file.write(f"Error on attempt {attempt}: {e}\n")
                raise 


def read_last_checked_time():
    try:
        with open('./config/time.txt', 'r', encoding='utf-8') as file:
            last_time_str = file.readline().strip()
        return datetime.fromisoformat(last_time_str)
    except FileNotFoundError:
        return datetime.min

def write_last_checked_time(time):
    with open('./config/time.txt', 'w', encoding='utf-8') as file:
        file.write(time.isoformat())

def parse_cve_time(cve_time_str):
    return datetime.fromisoformat(cve_time_str.replace('Z', '+00:00'))

if cvename :
    cve = getcve_details(cvename)
    res = create_cve_details(cve)
    matched_cves[cve['CVE']] = {**cve, **res}

url = "https://api.vulncheck.com/v3/index/nist-nvd2"
headers = {
    "cookie": "token=vulncheck_6973d6a0a88165b652e578ec9b415dc1de2048af6da4ae48f442a5885cca77a0"
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    data = response.json()
    cve_list = data['data']
    
    with open('./config/config.txt', 'r', encoding='utf-8') as file:
        keywords = [line.strip().lower() for line in file.readlines()]

    last_checked_time = read_last_checked_time()
    new_last_checked_time = datetime.now() 
    write_last_checked_time(new_last_checked_time) 
    
    
    for cve in cve_list:
        news_cve = {}
        published_time = parse_cve_time(cve['published'])
        
        if published_time > last_checked_time:
            description = cve['descriptions'][0]['value'].lower()
            if any(keyword in description for keyword in keywords):
                references = [ref['url'] for ref in cve.get('references', [])]
                
                cve_data = {
                    "CVE": cve['id'],
                    "Published": cve['published'],
                    "Description": cve['descriptions'][0]['value'],
                    "References": references
                }

                
                news_cve[cve['id']] = cve_data

    
    if news_cve:
        for cve,cve_data in news_cve:
            res = create_cve_details(cve_data)
            news_cve[cve] = {**cve, **res}
            
    all_cve = {**news_cve, **matched_cves}
    convert_json(all_cve)

else:
    print("error api:", response.status_code)

