from __future__ import print_function
import sys, warnings, os, csv
import deepsecurity
from deepsecurity.rest import ApiException
from pprint import pprint
import sqlite3
from time import time
import logging
import json
from collections.abc import Iterable
from progress.bar import Bar
from progress.spinner import MoonSpinner
from time import sleep
from termcolor import colored
from colorama import Fore, Back, Style


def initialConfig():
    # Setup
    if not sys.warnoptions:
        warnings.simplefilter("ignore")
    configuration = deepsecurity.Configuration()
    filename = "credentials.json"
    with open(filename) as json_file:
        data = json.load(json_file)
        print(data)
        for p in data['credential']:
            url = p['Url']
            api_key = p['ApiKey']
            print (url)
    configuration.host = url
    configuration.verify_ssl = "false"
    
    #Mensajes
    print("This is a help script for querying agents in Deep Security using the API.")
    print("Automation Center for References https://automation.deepsecurity.trendmicro.com/")
    print("©2020 by Trend Micro Incorporated. All rights reserved.")

    # Authentication
    configuration.api_key['api-secret-key'] = api_key
    api_version = "v1"
    print ("Connecting to %s ..."%configuration.host)
    #Create temporal BD with data from API
    conn = sqlite3.connect('all_ds_rules.db')
    #Crear tabla en BD Auxiliar
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS rules (id_rule varchar(5), rule_name varchar(100),severity varchar(25), cve varchar(250),cve_score varchar(25))")
    c.execute("CREATE TABLE IF NOT EXISTS hosts (id_host varchar(5), host_name varchar(100))")
    c.execute("CREATE TABLE IF NOT EXISTS rules_assin (id_rule varchar(5), id_host varchar(25))")
    c.execute("CREATE TABLE IF NOT EXISTS rules_recom (id_rule varchar(5), id_host varchar(25))")
    c.execute("DELETE FROM hosts;")
    c.execute("DELETE FROM rules_recom;")
    c.execute("DELETE FROM rules_assin;")
    #Capturar tiempo de inicio
    tiempo_inicial = time()
    getAllRules(configuration, conn, c, api_version, tiempo_inicial)
    getAgents(configuration, conn, c, api_version, tiempo_inicial)
    getRecommendedRules(configuration, conn, c, api_version, tiempo_inicial)
    conn.close()
    input("Enter any key to quit.")
    sys.exit()

def getCredentials():
	input("Enter any key to quit.")
	# sys.exit() is used to make the program quits. ( duh )
	sys.exit()

def getAllRules(configuration, conn, c, api_version, tiempo_inicial):
    c = conn.cursor()
    # Set Any Required Values
    api_instance = deepsecurity.IntrusionPreventionRulesApi(deepsecurity.ApiClient(configuration))
    search_filter = deepsecurity.SearchFilter()
    c.execute("SELECT count(id_rule) FROM rules;")
    TotalRegistries = c.fetchone()
    
    if TotalRegistries[0] < 5000:
        try:
            api_response = api_instance.search_intrusion_prevention_rules(api_version, search_filter=search_filter)
            with Bar('Downloading Deep Security rules...', max = 5000) as bar:
                for rule in api_response.intrusion_prevention_rules:
                    bar.next()
                    cve_score = rule.cvss_score
                    cveids = ""
                    if(cve_score == "0") or (cve_score == "-1"):
                        cve_score = "N/A"
                    if((rule.cve != None) and (len(rule.cve)>1)):
                        for cve in rule.cve:
                            cveids += cve+", " 
                    c.execute("INSERT INTO rules (id_rule, rule_name, severity, cve, cve_score) VALUES (?, ?, ?, ?, ?)",(rule.id, rule.identifier+" - "+rule.name, rule.severity, cveids, cve_score))
                conn.commit()
                c.close()
        except ApiException as e:
            print("An exception occurred: %s\n" % e)
    else:
        print("Downloading Deep Security rules...    [DONE]")
    
def getRuleID(conn, id_rule, configuration, api_version):
    c = conn.cursor()
    c.execute("SELECT id_rule FROM rules WHERE id_rule= ?", [id_rule])
    row = c.fetchone()
    if row is None:
        insertNewRuleID(conn, id_rule, configuration, api_version)
        return True
    else:
        return True
            
def insertNewRuleID(conn, id_rule, configuration, api_version):
    try:
        c = conn.cursor()
        c.execute("SELECT id_rule FROM rules WHERE id_rule= ?", [id_rule])
        row = c.fetchone()
        if row is None:
            api_instance = deepsecurity.IntrusionPreventionRulesApi(deepsecurity.ApiClient(configuration))
            rule_add = api_instance.describe_intrusion_prevention_rule(id_rule, api_version)
            cve_score = rule_add.cvss_score
            cveids = ""
            if(cve_score == "0") or (cve_score == "-1"):
                cve_score = "N/A"
            if((rule_add.cve != None) and (len(rule_add.cve)>1)):
                for cve in rule_add.cve:
                    cveids += cve+", " 
            c.execute("INSERT INTO rules (id_rule, rule_name, severity, cve, cve_score) VALUES (?, ?, ?, ?, ?)",(rule_add.id, rule_add.identifier+" - "+rule_add.name, rule_add.severity, cveids, cve_score))
            conn.commit()
            c.close()
    except Exception as e:
        logging.info('End Rules query')
        print(e)

def getAgents(configuration, conn, c, api_version, tiempo_inicial):
    c = conn.cursor()
    api_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
    expand_options = deepsecurity.Expand()
    overrides = False
    expand_options.add(expand_options.intrusion_prevention)
    expand = expand_options.list()
    try:
        api_response = api_instance.list_computers(api_version, expand=expand, overrides=overrides)
        with Bar('Saving agent information...    ', max = len(api_response.computers)) as bar:
            for computer in api_response.computers:
                bar.next()
                c.execute("INSERT INTO hosts (id_host, host_name) VALUES (?, ?)",(computer.id, computer.host_name))
        conn.commit()
        c.close() 
    except ApiException as e:
        print("An exception occurred: %s\n" % e)
    
def getRecommendedRules(configuration, conn, c, api_version, tiempo_inicial):
    try:
        c = conn.cursor()
        api_instance = deepsecurity.ComputerIntrusionPreventionRuleAssignmentsRecommendationsApi(deepsecurity.ApiClient(configuration))
        overrides = True
        c.execute("SELECT id_host FROM hosts;")
        computers = c.fetchall()
        all_database_rules = []
        with Bar('Searching Recommendations...   ',max = len(computers)) as bar:
            for computer in computers:
                bar.next()
                api_response = api_instance.list_intrusion_prevention_rule_ids_on_computer(computer[0], api_version, overrides=overrides)
                if(isinstance(api_response.recommended_to_assign_rule_ids, Iterable)):
                    for recommendedRule in api_response.recommended_to_assign_rule_ids:
                        all_database_rules.append(recommendedRule)
                        c.execute("INSERT INTO rules_recom (id_rule, id_host) VALUES (?, ?)", (recommendedRule, computer[0]))
                if(isinstance(api_response.assigned_rule_ids, Iterable)):
                    for assignedRule in api_response.assigned_rule_ids:
                        all_database_rules.append(assignedRule)
                        c.execute("INSERT INTO rules_assin (id_rule, id_host) VALUES (?, ?)",(assignedRule, computer[0]))
        print("Total recommendations: %s "%len(all_database_rules))
        updateRules(conn, all_database_rules, configuration, api_version)
        conn.commit()
        c.close()    
    except ApiException as e:
        print("An exception occurred: %s\n" % e)

def updateRules(conn, all_rules, configuration, api_version):
    aux_all_rules = list(dict.fromkeys(all_rules))
    with Bar('Updating Rules...              ', max=len(aux_all_rules)) as bar:
        for rule in aux_all_rules:
            insertNewRuleID(conn, rule, configuration, api_version)
            bar.next()
    queries(conn) 

def queries(conn):
    try:
        c = conn.cursor()
        print("Exporting information .....")
        c.execute("SELECT rules.rule_name as 'Rule Name', rules.severity as 'Severity', rules.cve_score as 'CVS Score', group_concat(hosts.host_name) as 'Host with rule Assigned' FROM rules_assin INNER JOIN rules ON rules_assin.id_rule=rules.id_rule INNER JOIN hosts ON hosts.id_host=rules_assin.id_host GROUP BY rules.rule_name;")
        print("Creating rules file assigned to agents ...")
        with open("rulesDataAssigned.csv", "w", newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow([i[0] for i in c.description])
            csv_writer.writerows(c)
        dirpath = os.getcwd() + "/rulesDataAssigned.csv"
        print ("Data exported Successfully into {}".format(dirpath))
        c.execute("SELECT rules.rule_name as 'Rule Name', rules.severity as 'Severity', rules.cve_score as 'CVS Score', group_concat(hosts.host_name) as 'Host with rule Assigned' FROM rules_recom INNER JOIN rules ON rules_recom.id_rule=rules.id_rule INNER JOIN hosts ON hosts.id_host=rules_recom.id_host GROUP BY rules.rule_name;")
        print("Creating recommended rules file for assigned to agents ...")
        with open("rulesDataRecommended.csv", "w", newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow([i[0] for i in c.description])
            csv_writer.writerows(c)
        dirpath = os.getcwd() + "/rulesDataRecommended.csv"
        print ("Data exported Successfully into {}".format(dirpath))
        c.close()
    except Exception as e:
        print("An exception occurred: %s\n" % e)
   
initialConfig()