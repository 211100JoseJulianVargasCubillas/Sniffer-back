from scapy.all import *
import mysql.connector

#connection to database
coneccion = mysql.connector.connect(user='root', password='Pedorriux19', host='127.0.0.1', database='practice_arqui')

#wrinter function
cursor=coneccion.cursor()

#sql command
add_all=("INSERT INTO sniff(mac_src,mac_des,ip_src,tam_src,ip_des,tam_des) VALUES (%s,%s,%s,%s,%s,%s)")

# callback function - called for every packet
def traffic_monitor_callbak(pkt):
    if "IP" in pkt:

#sniff variables
        ip_src=pkt["IP"].src
        tam_ip_src=pkt["IP"].len
        ip_des=pkt["IP"].dst
        tam_ip_des=pkt["IP"].len
        mac_src=pkt.src
        mac_des=pkt.dst

#print on console the data got  from the sniffers
        print (ip_src)
        print (tam_ip_src)
        print (ip_des)
        print (tam_ip_des)
        print (mac_src)
        print (mac_des)

#commit the data to db
        cursor.execute(add_all, (mac_src,mac_des,ip_src,tam_ip_src,ip_des,tam_ip_des,))
        coneccion.commit()

# capture traffic
sniff(prn=traffic_monitor_callbak, store=0, timeout=30)