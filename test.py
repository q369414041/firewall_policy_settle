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
    firewall_policy = firewall_policy.replace('\nexit\nl2', '').replace('\nexit', '')
    firewall_rule = firewall_policy.replace('\nrule', ' rule').replace('\n', '').replace('  ', ' ').replace('rule ','rule').split(" ")
    print(firewall_rule)

def catch_file():
    for i in catch_folder():

        with open(f'{i}/show-configuration.log','r') as fp:
            ip_book = fp.read()
        if 'Version 4.0' in ip_book:
            continue
            #firewall_policy = re.compile('rule id.*exit\nl2', re.S).findall(ip_book)

        elif 'no tcp-syn-check' in ip_book:
            print(i)
            firewall_policy = re.compile('rule id.*exit\nno', re.S).findall(ip_book)
            firewall_policy_clear(firewall_policy)
        else:
            #正则抓数据
            firewall_policy = re.compile('rule id.*exit\nl2',re.S).findall(ip_book)
            firewall_policy_clear(firewall_policy)


def rule_id_judgment(rule_id,key):
    if rule_id.get(key) == None:
        return ['NUll']
    elif rule_id.get(key) == ['permit']:
        return ['"permit"']
    else:
        return rule_id.get(key)

def file_clear(n):
    for i in catch_file():
        if i == 'ruleid':
            rule_id = {'rule id':[f'{n}']}
            n += 1
        elif i in '12345678910111213141516171819202122232425262728293031323334353637383940' :
            if n > 1:
                for af in range(0, len(rule_value), 2):
                    rule_id_value.setdefault(rule_value[af], []).append(rule_value[af + 1])
                rule_id.update(rule_id_value)
                rule_sql = f'INSERT INTO TPL_filiale VALUES ("TPP-SHENZHEN-10.112.96.223",' \
                           f'{"".join(rule_id.get("rule id"))},' \
                           f'{"".join(rule_id_judgment(rule_id,"action"))},' \
                           f'{"".join(rule_id.get("src-zone"))},' \
                           f'{"".join(rule_id.get("dst-zone"))},' \
                           f'{"".join(rule_id.get("src-addr"))},' \
                           f'{"".join(rule_id.get("dst-addr"))},' \
                           f'{"".join(rule_id.get("service"))},' \
                           f'{"".join(rule_id_judgment(rule_id,"description"))},' \
                           f'{"".join(rule_id_judgment(rule_id,"name"))})'
                use_mysql(rule_sql)
                rule_id_value.clear()
                rule_value.clear()
                # print(firewall_rule_jason_true)
        else:
            rule_value.append(i)

if __name__ == '__main__':
    catch_file()