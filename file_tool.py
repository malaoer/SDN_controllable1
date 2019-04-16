# -*- coding:utf-8 -*-
import json
import csv
import cx_Oracle

def read_network_conf():
    with open(".//configuration//network_conf.json","r") as f:
        file_dict = json.load(f)
        print(file_dict)
        Con_IP = file_dict['Con_IP']
        Con_port = file_dict['Con_port']
        return Con_IP,Con_port

def read_policy_file():
    """
    读取polocy.csv文件，将csv文件转换为字典列表
    :return:
    """
    dict_list = []
    with open(".//data//already_policy.csv", newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            dict_list.append(row)
    return dict_list

def read_policy_file1():
    """
    读取polocy.csv文件，将csv文件转换为字典列表
    :return:
    """
    dict_list = []
    with open(".//data//policy.csv", newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            dict_list.append(row)
    return dict_list
def write_dict_to_csv(csv_columns,dict_data):
    try:
        with open(".//data//output.csv", 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for data in dict_data:
                writer.writerow(data)
    except IOError as err:
            print("I/O error{0}: ".format(err))
    return

def search_policy_form_oracle(sql):
    conn = cx_Oracle.connect('SYSTEM', 'root', '172.21.22.179:1521/xe')
    cursor = conn.cursor()
    cursor.execute(sql)
    rows = cursor.fetchall()
    conn.commit()
    cursor.close()
    conn.close()
    return rows

def csv_import_oracle_policy():
    conn = cx_Oracle.connect('SYSTEM', 'root', '172.21.22.179:1521/xe')
    cursor = conn.cursor()
    file_name = './/data//policy.csv'
    insert_line = 0
    f = open(file_name)
    csv_reader  = csv.reader(f)
    for i,row_data in enumerate(csv_reader):
        if i > 0:
            if row_data:
                value = tuple(row_data)
                print(value)
                sql_insert = "insert into policy values ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')"%(value[0].strip(),value[1].strip(),value[2].strip(),value[3].strip(),value[4].strip(),value[5].strip(),value[6].strip(),value[7].strip(),value[8].strip(),value[9].strip(),value[10].strip(),value[11].strip(),value[12].strip() )
                cursor.execute(sql_insert)
                insert_line += 1
    f.close()
    conn.commit()
    cursor.close()
    conn.close()

def oracle_to_csv_policy() :
    # 从数据库中读取策略
    conn = cx_Oracle.connect('SYSTEM', 'root', '172.21.22.179:1521/xe')
    cursor = conn.cursor()
    printHeader = True  # include column headers in each table output
    sql = "select * from policy"  # get a list of all tables
    rows = cursor.execute(sql)
    for row_data in rows:
        print(row_data)

        if not row_data[0].startswith('BIN$'):  # skip recycle bin tables
            tableName = row_data[0]
            print(tableName)
            # output each table content to a separate CSV file
            csv_file_dest = ".//data//export_policy.csv"
            outputFile = open(csv_file_dest, 'w')  # 'wb'
            output = csv.writer(outputFile, dialect='excel')
            sql = "select * from policy"
            curs2 = conn.cursor()
            curs2.execute(sql)
            if printHeader:  # add column headers if requested
                cols = []
                for col in curs2.description:
                    cols.append(col[0])
                output.writerow(cols)
            for row_data in curs2:  # add table rows
                output.writerow(row_data)
            outputFile.close()

def delete_oracle_policy(aasno):
    conn = cx_Oracle.connect('SYSTEM', 'root', '172.21.22.179:1521/xe')
    cursor = conn.cursor()
    sql =  "delete  from policy where AASNO=%s "% aasno
    print(sql)
    cursor.execute(sql)
    conn.commit()
    cursor.close()
    conn.close()

def insert_policy_oracle(policy):
    conn = cx_Oracle.connect('SYSTEM', 'root', '172.21.22.179:1521/xe')
    cursor = conn.cursor()
    value = policy.split(',')
    sql = "insert into policy values ('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')" % (
                value[0].strip(), value[1].strip(), value[2].strip(), value[3].strip(), value[4].strip(), value[5].strip(),
                value[6].strip(), value[7].strip(), value[8].strip(), value[9].strip(), value[10].strip(), value[11].strip(),
                value[12].strip())
    cursor.execute(sql)
    conn.commit()
    cursor.close()
    conn.close()


# sql = 'select * from policy'
# rows = search_policy_form_oracle(sql)
# for row in rows:
#     print(row)

# csv_import_oracle_policy()
# oracle_to_csv_policy()
#delete_oracle_policy('10')
insert_policy_oracle('10,156,3,00:00:00:00:00:00,00:00:00:00:00:00,123.40.0.0/13,94.128.0.0/9,84,133,61,120,6,Allow')