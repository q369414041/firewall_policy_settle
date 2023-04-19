import re
import pymysql
import os
import glob

rule_value = []
rule_id_value= {}
n = 0

def use_mysql(sql):
# 打开数据库连接
    db = pymysql.connect(host='localhost',
                         user='quangy',
                         password='Sdari@100',
                         database='test_mysql')
    cursor = db.cursor()

    try:
         # 执行sql语句
        cursor.execute(sql)
        # 提交到数据库执行
        db.commit()
    except:
         # 如果发生错误则回滚
        db.rollback()
        # 关闭数据库连接
        db.close()


#分支机构巡检文件夹路径名
def catch_folder():
    folder_path = "/Users/quanguangyuan/Desktop/1/"
    return glob.glob(os.path.join(folder_path, '*'))

# 清洗数据使数据转化为规律列表
def firewall_policy_clear(firewall_policy):
    firewall_policy = ''.join(firewall_policy)
    # 清洗数据使数据转化为规律列表
    firewall_policy = firewall_policy.replace('\nexit\nl2', '').replace('\nexit\nno t', '').replace('\nexit', '')
    firewall_rule = firewall_policy.replace('\nrule', ' rule').replace('\n', '').replace('  ', ' ').replace('rule ','rule').replace('disable ',"").split(" ")
    return firewall_rule

def catch_file():
    for i in catch_folder():
        with open(f'{i}/show-configuration.log','r') as fp:
            ip_book = fp.read()
        if 'Version 4.0' in ip_book:
            continue
            #firewall_policy = re.compile('rule id.*exit\nl2', re.S).findall(ip_book)

        elif 'no tcp-syn-check' in ip_book:
            firewall_policy = re.compile('rule id.*exit\nno t', re.S).findall(ip_book)
            fw_cl = firewall_policy_clear(firewall_policy)
            fw_ip = i.replace('/Users/quanguangyuan/Desktop/1/', '')
            print(fw_ip)
            file_clear(fw_cl, n, fw_ip)
        else:
            #正则抓数据
            firewall_policy = re.compile('rule id.*exit\nl2',re.S).findall(ip_book)
            fw_cl = firewall_policy_clear(firewall_policy)
            fw_ip = i.replace('/Users/quanguangyuan/Desktop/1/','')
            print(fw_ip)
            file_clear(fw_cl,n,fw_ip)
    # with open('/Users/quanguangyuan/Desktop/1/0701440140012024-10.108.7.223-202303271125/show-configuration.log') as fp:
    #     ip_book = fp.read()
    # firewall_policy = re.compile('rule id.*exit\nno', re.S).findall(ip_book)
    # fw_cl = firewall_policy_clear(firewall_policy)
    # fw_ip = '0701440140012024-10.108.7.223-202303271125'
    # file_clear(fw_cl,n,fw_ip)

def rule_id_judgment(rule_id,key):
    if rule_id.get(key) == None:
        return ['NUll']
    elif rule_id.get(key) == ['permit']:
        return ['"permit"']
    else:
        return rule_id.get(key)

def sql_statement(rule_id,fw_ip):
    for af in range(0, len(rule_value), 2):
        rule_id_value.setdefault(rule_value[af], []).append(rule_value[af + 1])
    rule_id.update(rule_id_value)
    rule_sql = f'INSERT INTO TPL_filiale VALUES ("{fw_ip}",' \
               f'{"".join(rule_id.get("rule id"))},' \
               f'{"".join(rule_id_judgment(rule_id, "action"))},' \
               f'{"".join(rule_id_judgment(rule_id, "src-zone"))},' \
               f'{"".join(rule_id_judgment(rule_id, "dst-zone"))},' \
               f'{"".join(rule_id_judgment(rule_id, "src-addr"))},' \
               f'{"".join(rule_id_judgment(rule_id, "dst-addr"))},' \
               f'{"".join(rule_id_judgment(rule_id, "service"))},' \
               f'{"".join(rule_id_judgment(rule_id, "description"))},' \
               f'{"".join(rule_id_judgment(rule_id, "name"))},' \
               f'"{"".join(rule_id_judgment(rule_id,"log"))}")'
    use_mysql(rule_sql)
    rule_id_value.clear()
    rule_value.clear()

def file_clear(fw_cl,n,fw_ip):
    for v, i in enumerate(fw_cl):
        if i == 'ruleid':
            rule_id = {'rule id':[f'{n}']}
            n += 1
        elif i.isdigit() is True:
            if n > 1:
                sql_statement(rule_id,fw_ip)
        elif v != len(fw_cl)-1:
            rule_value.append(i)
        else:
            rule_value.append(i)
            rule_id = {'rule id': [f'{n}']}
            sql_statement(rule_id,fw_ip)
if __name__ == '__main__':
    catch_file()
