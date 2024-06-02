import requests
import os
from datetime import datetime
from markdown import markdown
import time
from datetime import datetime
import re
import json
import argparse
from html.parser import HTMLParser


parser = argparse.ArgumentParser(description='دریافت cvename از خط فرمان')
parser.add_argument('--cvename', type=str, default='', help='نام CVE (اگر وجود دارد)')

args = parser.parse_args()

cvename = args.cvename

matched_cves = {}

all_cve = {}


khoj_token = os.getenv('KHOJ_TOKEN')
vulncheck = os.getenv('VULNCHECK_TOKEN')

def send_cve_message_to_telegram(cve_data):
    try:
        # Generate message from JSON data
        message = f"🟢 [{cve_data['id']}]({cve_data['link']})  \n\n"
        message = f"🚨 **عنوان**: {cve_data['title']}  \n\n"
        message += f"📣 **منابع**: {cve_data['source']} \n\n "
        message += f"📓 **خلاصه**: {cve_data['summary']} \n\n  "
        message += f"📅 **تاریخ انتشار**: {cve_data['publish_date']}  \n\n  "
        message += f"😈 **شرح آسیب پذیری**: {cve_data['info']} \n\n "
        message += f"🏷️ **برچسب**: {', '.join(cve_data['tags'])} \n\n "
        message += f"🏷️ *چارت*: {', '.join(cve_data['chart'])} \n\n "

        telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')
        telegram_thread_id = os.getenv('TELEGRAM_THREAD_ID')


        if not telegram_bot_token:
            raise ValueError("TELEGRAM_BOT_TOKEN wasn't configured in the secrets!")
        
        if not telegram_chat_id:
            raise ValueError("TELEGRAM_CHAT_ID wasn't configured in the secrets!")
        
        if not telegram_thread_id:
            raise ValueError("TELEGRAM_THREAD_ID wasn't configured in the secrets!")
        
        # Send message to Telegram
        url = f'https://api.telegram.org/bot{telegram_bot_token}/sendMessage?chat_id={telegram_chat_id}&message_thread_id={telegram_thread_id}&text={message}&parse_mode=Markdown'

        response = requests.get(url)
        
        if response.status_code != 200:
            raise Exception(f"Failed to send message: {response.status_code}")
        else:
            print("Message sent successfully")
        
        resp = response.json()
        if not resp['ok']:
            raise Exception(f"Telegram API error: {resp['description']}")
    
    except Exception as e:
        with open("./log/logs.txt", "a") as log_file:
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

        text = cve_data['info']


        data = {
        'id': cve_data["CVE"],
        'tags': cve_data["tags"],
        'source': "زفتا",
        'title': cve_data["title"],
        'link': "https://nvd.nist.gov/vuln/detail/" + cve_data["CVE"],
        'summary': f"{text[:200]} ... ",
        'info': f"{cve_data['info']}\n\n   راهکار امن سازی :   {cve_data['remedition']}" ,
        'publish_date': convert_datetime_format(cve_data['Published']),
        'chart': cve_data['chart'],
        }

        print(f'file {cve_data["CVE"]} created')

        # Dump the data to JSON with proper indentation and encoding
        json_data = json.dumps(data, ensure_ascii=False, indent=4)
        with open(file_name, 'w', encoding='utf-8') as file:
            file.write(json_data)

        print(f'sending {cve_data["CVE"]} to telegram ...')

        send_cve_message_to_telegram(data)




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
                print(f"Sending prompt to khoj ...")
                res = RAG(final_prompt)
                if "Too Many Requests" in res:
                    raise Exception("Too Many Requests: Please slow down.")
                if key == 'title':  
                    res = remove_compiled_section(res)
                    match = re.search(r'\[([^\]]+)\]', res).group(1)
                    ai_dic[key] = match
                    print(f"create title for {cve['CVE']}")
                elif key == 'tags':
                    res = remove_compiled_section(res)
                    tags = re.findall(r'\[([^\]]+)\]', res)
                    ai_dic[key] = tags
                    print(f"create tags for {cve['CVE']}")
                elif key == 'chart':
                    res = remove_compiled_section(res)
                    print(res)
                    matches = re.search(r'\\?\[(\d+(?:,\s*\d+)*)\\?\]', res)
                    try:
                        numbers = matches.group(1)
                        chart = [i.strip() for i in numbers.split(',')]
                    except:
                        chart = [0]
                    ai_dic[key] = chart
                    print(f"create chart for {cve['CVE']}")
                else: 
                    res = remove_compiled_section(res)
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
    "tags" : "چند تا برچسب به انگلیسی برای آسیب پذیری {{ID}} بهم بده در برچسب از نوشتن امتیاز خودداری بکن و فقط برچسب های کلی را بنویس هر هر بچسب را داخل [] بنویس ",
    "chart" : "با توجه به به آسیب پذیری با شناسه {{ID}} اگر در مورد دیتابیس بود عدد 17 را بهم نمایش بده اگر در مورد سیستم عامل بود عدد 16 و 17 و 2 و اگر در مورد تجهیزات بود مثل سیسکو ، فورتیگیت ، استوریج و .. عدد 16 و 4 و اگر در مورد سایت وب اپلیکیشن و وب سرور بود 17 و 18 را برایم در خروجی نمایش بده و اینکه حتما اعداد را داخل [] بگذار",
    "title" : "یک عنوان به زبان فارسی برای آسیب پذیری با شناسه {{ID}} بهم بده با توجه به منابع {{REF}} و در آن فقط و فقط و فقط نام CVEو دستگاه آسیب پذیر را بنویس و حتما آن را داخل [] قرار بده",
    "info" : "یک توضیح کامل در مورد آسیب پذیری با شناسه {{ID}} با منابع {{REF}} به زبان فارسی بهم بده و هیچ توضیحی در خصوص راهکار امن سازی نده و در متنی که بهم میدی هم سوال از من نپرس",
    "remedition" : "یک راهکار امن سازی برای آسیب پذیری با شناسه {{ID}} بهم بده با توجه به منابع {{REF}} و اگر در ورژن های بعدی آسیب پذیری رفع شده بود ورژن امن را در آخر بهم بگو و در متن هم از من سوال نپرس",
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
                #'Authorization': f'Bearer {khoj_token}',
                'cookie': f"session={khoj_token}",
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

            print(response.text)


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
    "cookie": f"token={vulncheck}"
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    data = response.json()
    cve_list = data['data']
    
    with open('./config/config.txt', 'r', encoding='utf-8') as file:
        keywords = [line.strip().lower() for line in file.readlines()]

    last_checked_time = read_last_checked_time()
    new_last_checked_time = datetime.now() 
    
    news_cve = {}
    keyword_check = False
    for cve in cve_list:
        published_time = parse_cve_time(cve['published'])
        if published_time > last_checked_time:
            description = cve['descriptions'][0]['value'].lower()
            if "rejected reason" not in description:
                if any(keyword in description for keyword in keywords) or not keyword_check:
                    references = [ref['url'] for ref in cve.get('references', [])]
                
                    cve_data = {
                        "CVE": cve['id'],
                        "Published": cve['published'],
                        "Description": cve['descriptions'][0]['value'],
                        "References": references
                    }

                
                    news_cve[cve['id']] = cve_data

    if news_cve:
        print(news_cve)
        for cve,cve_data in news_cve.items():
            res = create_cve_details(cve_data)
            news_cve[cve] = {**cve_data, **res}

            
    all_cve = {**news_cve, **matched_cves}
    convert_json(all_cve)
    

    write_last_checked_time(new_last_checked_time) 

else:
    print("error api:", response.status_code)

