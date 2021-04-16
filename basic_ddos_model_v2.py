# -*- coding: utf-8 -*-
"""
Created on Tue Oct 27 15:58:30 2020

@author: tt
"""


from scapy.all import *
from scapy.layers.dns import *
import json
import datetime
import pandas as pd
from pandas.io.json import json_normalize
import struct
import numpy as np
import copy
from sklearn.ensemble import RandomForestClassifier 
from sklearn.ensemble import RandomForestRegressor
from sklearn.feature_selection import SelectFromModel
from sklearn.feature_extraction.text import CountVectorizer
import nltk
from nltk.tokenize import word_tokenize
from datetime import datetime
from sklearn import preprocessing
from sklearn.model_selection import  cross_val_score
import matplotlib.pyplot as plt
from sklearn.externals import joblib
src_hgc = "./pcap/test.pcap"#q1_benign_00000_20190125202922
dst_hgc = "./pcap/testing.json"

#limit = 5000000
limit = -1
count = 0
pkts = []
maxlen_qr=[]
maxlen_an=[]
max_qr=0
max_an=0

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, bytes):
            return str(obj, encoding='utf-8');
        return json.JSONEncoder.default(self, obj)
 
def func(pkt):
	global pkts, count, limit,pct_curr,maxlen_qr,maxlen_an,mm,nn
	
	
	
	arrival_time=datetime.datetime.fromtimestamp(pkt.time)
	arrival_t=arrival_time.strftime("%Y-%m-%d %H:%M:%S")
	
	srcip, dstip, proto, sport, dport = None, None, None, None, None
	ID,qr,opcode,aa,tc,rd,ra,z,rcode=0,0,0,0,0,0,0,0,0
	qdcount,ancount,nscount,arcount,qd,an,ns,ar=None,None,None,None,None,None,None,None
	QD,AN=None,None
	
	#print(pkt.show())
	if pkt.haslayer(IP):
		srcip = pkt[IP].src
		dstip = pkt[IP].dst
		proto = pkt[IP].proto
		if pkt.haslayer(TCP):
			sport = pkt[TCP].sport
			dport = pkt[TCP].dport
		elif pkt.haslayer(UDP):
			sport = pkt[UDP].sport
			dport = pkt[UDP].dport
			bytecnt=len(pkt[UDP])-8
			if pkt.haslayer(DNS):
				dns_1=pkt.getlayer(DNS)
				queryarrs=[]
				answerarrs=[]
				#bytecnt=dns_1.length
				ID=dns_1.id
				qr=dns_1.qr
				opcode=dns_1.opcode
				aa=dns_1.aa
				#print("type aa is",type(aa))
				tc=dns_1.tc
				rd=dns_1.rd
				ra=dns_1.ra
				z=dns_1.z
				rcode=dns_1.rcode
				qdcount=dns_1.qdcount
				ancount=dns_1.ancount
				nscount=dns_1.nscount
				arcount=dns_1.arcount
				m=1
				if(dns_1.getlayer(DNSRR)==None):
					wyt=0
					
				else:
					an=dns_1.getlayer(DNSRR,nb=m)
					
					while an != None:
						#print(type(an.rclass),type(an.type),type(an.ttl))
						rr_name=str(an.rrname,encoding = "utf-8")
						
						r_data=""
						r_len=""
						
						if(type(an.rdata)==bytes):
							
# 							r_data=str(an.rdata,encoding = "utf-8")
							rdt=an.rdata
								
# 								
								
							if(isinstance(rdt,list)):
								lisposition=0
								rd_2=""
								while lisposition< len(rdt):
									
									temp=str(rdt[lisposition],encoding = "utf-8")
									rd_2=rd_2+temp+"\\"
									lisposition=lisposition+1
							else:
								rd_2=str(rdt)
							if(type(an.rdlen)==bytes):
								print("rdlen is bytes")
								#print(repr(an.rdlen))
# 								r_len=struct.unpack("H",an.rdlen)
								r_len=an.get_field('rdlen').i2m(an,an.rdlen)
								
							else:
								
# 								print(type(an.rdlen.i2m(pkt)))
# 								print(an.rdlen.i2m(pkt))
# 								
								r_len=an.get_field('rdlen').i2m(an,an.rdlen)
							#print(type(an.rclass),type(rr_name),type(an.type))
							#print(type(rd_2),type(r_len),type(an.ttl))
							an_curr={"qclass":an.rclass,"qname":rr_name,"qtype":an.type,"rdata":rd_2,"rdlength":r_len,"ttl":an.ttl}
						else:
							
							if(type(an.rdlen)==bytes):
								print("rdlen is bytes")
								#print(repr(an.rdlen))
								r_len=an.get_field('rdlen').i2m(an,an.rdlen)
# 								r_len=struct.unpack("H",an.rdlen)#bBHhiIl
								rdt=an.rdata
								
# 								
								
								if(isinstance(rdt,list)):
									lisposition=0
									rd_2=""
									while lisposition< len(rdt):
										temp=str(rdt[lisposition],encoding = "utf-8")
										rd_2=rd_2+temp+"\\"
										lisposition=lisposition+1
								else:
									rd_2=str(rdt)
							else:
# 								print("----")
# 								bbb=struct.unpack('!h',an.rdlen)[0]
# 								print(an.rdlen.i2m(pkt))
# 								print(type(an.rdlen.i2m(pkt)))
								rdt=an.rdata
								
# 								
								
								if(isinstance(rdt,list)):
									lisposition=0
									rd_2=""
									while lisposition< len(rdt):
										temp=str(rdt[lisposition],encoding = "utf-8")
										rd_2=rd_2+temp+"\\"
										lisposition=lisposition+1
								else:
									rd_2=str(rdt)
								r_len=an.get_field('rdlen').i2m(an,an.rdlen)
								
							#print(type(an.rclass),type(rr_name),type(an.type))
							#print(type(rd_2),type(r_len),type(an.ttl))
							an_curr={"qclass":an.rclass,"qname":rr_name,"qtype":an.type,"rdata":rd_2,"rdlength":r_len,"ttl":an.ttl}
						answerarrs.append(an_curr)
						#print("m=",m)
						m=m+1
						an=dns_1.getlayer(DNSRR,nb=m)
					print(m-1)
# 					print(arcount,ancount,nscount,'/',arcount+ancount+nscount,'/',m-1,'/',maxlen_an)
				
				
				n=1
				qd=dns_1.getlayer(DNSQR,nb=n)
				while qd != None:
					
				
					q_name=str(qd.qname,encoding = "utf-8")
					#print(type(qd.qclass),type(qd.qtype))
					#print(type(qd.qclass),type(q_name),type(qd.qtype))
					qd_curr={"qclass":qd.qclass,"qname":q_name,"qtype":qd.qtype}
					queryarrs.append(qd_curr)
					#print("n=",n)
					n=n+1
					qd=dns_1.getlayer(DNSQR,nb=n)
				print(n-1)
				
# 					response.meta['maxlen_qr']=n-1
				#print(type(aa),type(ancount),type(answerarrs))
# 				print("=========")
# 				print(type(arcount),type(bytecnt),type(arrival_t))
# 				print(type(nscount),type(opcode),type(proto))
				#print(type(qr),type(qdcount),type(queryarrs))
# 				print(type(ra),type(rcode),type(rd))
# 				print("=========")
				#print(type(tc),type(ID),type(z))
# 				keys_1 = [str(x) for x in np.arange(len(queryarrs))]
# 				dict_queryarrs= dict(zip(keys_1, queryarrs))
# 				keys_2 = [str(x) for x in np.arange(len(answerarrs))]
# 				dict_answerarrs= dict(zip(keys_2, answerarrs))
# 				
# 				dict_additionalarrs={}
				
				mm=m-1
				nn=n-1
				pct_curr={"aa":aa,"additionalarrs":[],"additionalnum":0,"ancount":ancount,"answerarrs":answerarrs,"answernum":m-1,"arcount":arcount,"authorityarrs":[],"authoritynum":0,"bytecnt":bytecnt,"dnstime":arrival_t,"dport":dport,"dst_s":dstip,"ethernettime":arrival_t,"id":"","nscount":nscount,"opcode":opcode,"pckcnt":1,"protocol":proto,"ptype":4,"qdcount":qdcount,"qr":qr,"queryarrs":queryarrs,"querynum":n-1,"ra":ra,"rcode":rcode,"rd":rd,"sensorid":"","sessionid":"","sport":sport,"src_s":srcip,"tc":tc,"transactionid":ID,"zero":z}
				
				   
            
	if srcip and dstip and proto and sport and dport:
		pkts.append(pct_curr)
		maxlen_an.append(mm)
		maxlen_qr.append(nn)
# 		max_an=response.meta['maxlen_an']
# 		max_qr=response.meta['maxlen_qr']
		count = count + 1
	if limit > 0 and count >= limit:
		return True
	else:
		return False
 
def transform(src, dst, n_pkts = -1):
	global limit, count, pkts,maxlen_qr,maxlen_an,max_an,max_qr
	
	limit = n_pkts
	count = 0
	pkts = []
	maxlen_qr=[]
	maxlen_an=[]
	sniff(offline=src, stop_filter=func, store=False)#meta={'maxlen_an':copy.deepcopy(maxlen_an),'maxlen_qr':copy.deepcopy(maxlen_qr)}
# 	print(pkts)
	print(maxlen_an)
	max_qr=0
	for entry1 in maxlen_qr:
		if(entry1>max_qr):
			max_qr=entry1
	max_an=0
	for entry2 in maxlen_an:
		if entry2>max_an:
			max_an=entry2
	test_pkts=[{"aa":1,"bb":2,"cc":[],"dd":[{"aa":1,"bb":2}]},{"aa":1,"bb":2}]
	keys = [str(x) for x in np.arange(len(pkts))]
	dict_pkts= dict(zip(keys, pkts))
	
	data_bf={}
	data=json.loads(json.dumps(data_bf))
	data["data"]=pkts
	data["type"]="meta_dns"
	data["ip"]=""
	
	article = json.dumps(data, cls=MyEncoder,ensure_ascii=False)
	
	with open(dst, "w") as f:
		f.write(article)

# with open('./pcap/format.1604383830304.json','r',encoding="utf-8")as fp:
#     json_data = json.load(fp)
#     print('这是文件中的json数据：',json_data)
#     print('这是读取到文件数据的数据类型：', type(json_data))

def json_to_dataframe():
	
	
	with open("D:/dns/pcap/benign_new.json","r",encoding="gbk")as fp:
		info=fp.read()
		
		
		raw=json.loads(info)
		
		
		data=raw["data"]
		df = pd.DataFrame.from_dict(json_normalize(data), orient='columns')
		df1=pd.DataFrame(df["queryarrs"].values.tolist())
		#print(df1.head(n=5))	
		#print(df["queryarrs"].head(n=5))
		#print(df1.info())
		#print("maxlen_qr=",maxlen_qr)
		for i in range(max_qr):
			df3=df1[i].apply(pd.Series)
			df= pd.concat([df,df3],axis=1)
		df=df.drop(["queryarrs"],axis=1)
		#df.to_csv("./pcap/result.csv")
		print(max_qr)
		print(max_an)
		df4=pd.DataFrame(df["answerarrs"].values.tolist())
# 		print(df4.head(n=5))	
# 		print(df["answerarrs"].head(n=5))
# 		print(df4.info())
# 		print("maxlen_an=",maxlen_an)
		for i in range(max_an):
			df5=df4[i].apply(pd.Series)
			df= pd.concat([df,df5],axis=1)
		df=df.drop(["answerarrs"],axis=1)

		df=df.drop(["sensorid"],axis=1)
		df=df.drop(["sessionid"],axis=1)
		
		
		df.info()
		
		dict_test=dict(list(df.groupby('qr')))
		
		df_req=dict_test[1]
		
		df_res=dict_test[0]
		df_req.to_csv("./pcap/benign_res_new.csv")
		df_res.to_csv("./pcap/benign_req_new.csv")
		
		
def data_preprocessing():
	
	df_res=pd.read_csv("./pcap/ddos_res_new.csv")
	df_req=pd.read_csv("./pcap/ddos_req_new.csv")
# 	df_ddos=pd.concat([df_res,df_req])
	df_res['isddos']=[1 for index in range(len(df_res))]
	df_req['isddos']=[1 for index in range(len(df_req))]
	df_benign=pd.read_csv("./pcap/benign_res_new.csv")
	df_benign_req=pd.read_csv("./pcap/benign_req_new.csv")
	df_benign['isddos']=[0 for index in range(len(df_benign))]
	df_benign_req['isddos']=[0 for index in range(len(df_benign_req))]
	df_benign_1=df_benign.iloc[:10000,]
	df_benign_2=df_benign.iloc[10000:50000,]
	df_benign_3=df_benign.iloc[50000:,]
# 	df_ddos=pd.concat([df_res,df_benign_1])
# 	df_ddos=pd.concat([df_res,df_benign_2])
	df_ddos=pd.concat([df_req,df_benign_2])
# 	df_b_res=pd.read_csv("./pcap/benign_res_new.csv")
# 	df_b_req=pd.read_csv("./pcap/benign_req_new.csv")
# 	df_b=pd.concat([df_b_res,df_b_req])
# 	df_b['isddos']=0
# 	df_final=pd.concat([df_b,df_ddos])
	max_an_benign=16
	max_an_ddos=16
# 	df_req=pd.read_csv("./pcap/ddos_req.csv")
	df_ddos.info()
	print(df_ddos.columns.values.tolist())
	array_util=[1,28]
	
	for index, row in df_ddos.iterrows():
		
		for i,v in row.items():
			if i=='qtype.1':
				
				if np.isnan(v):
					
					
					df_ddos.loc[int(index),'answerIsNull']=1
					
					df_ddos.loc[int(index),'qtype.1']=array_util[random.randint(0,1)]
				else:
					
					df_ddos.loc[int(index),'answerIsNull']=0
					
							
			elif 'qtype.' in i:
				if np.isnan(v):
					df_ddos.loc[int(index),i]=array_util[random.randint(0,1)]
					print('fill',index,i)
			elif 'rdlength' in i:
				if np.isnan(v):
					df_ddos.loc[int(index),i]=0
			elif 'ttl' in i:
				if np.isnan(v):
					df_ddos.loc[int(index),i]=0
			elif 'qname.' in i:
				
				if v is np.nan:
					df_ddos.loc[int(index),i]=''
				
				
				
					
					
				
# 			if i=='qtype.2':
# 				if np.isnan(v):
# 					df_res.loc[index,'qtype.2']=array_util[random.randint(0,1)]
# 			if i=='qtype.3':
# 				if np.isnan(v):
# 					df_res.loc[index,'qtype.3']=array_util[random.randint(0,1)]
	colist_1=['rdlength']
	for ii in range(1,max_an_ddos):
		rdlencol='rdlength.'+str(ii)
		colist_1.append(rdlencol)
		
	df_ddos['rdlength_avg']=df_ddos[colist_1].sum(axis=1)
	colist_2=['ttl']
	
	for dd in range(1,max_an_ddos):
		ttlcol='ttl.'+str(dd)
		rdatacol='rdata.'+str(dd)
		df_ddos=df_ddos.drop([rdatacol],axis=1)
		colist_2.append(ttlcol)
		
	df_ddos['ttl_avg']=df_ddos[colist_2].sum(axis=1)
	df_ddos=df_ddos.drop(colist_2,axis=1)
	df_ddos=df_ddos.drop(colist_1,axis=1)
	for index_qclass in range(1,max_an_ddos+1):
		qclasscol='qclass.'+str(index_qclass)
		df_ddos=df_ddos.drop([qclasscol],axis=1)
	df_ddos=df_ddos.drop(['qclass'],axis=1)
	df_ddos=df_ddos.drop(['src_s'],axis=1)
	df_ddos=df_ddos.drop(['dst_s'],axis=1)
	df_ddos=df_ddos.drop(['additionalarrs'],axis=1)
	df_ddos=df_ddos.drop(['authorityarrs'],axis=1)
	df_ddos=df_ddos.drop(['id'],axis=1)
	df_ddos=df_ddos.drop(['rdata'],axis=1)
	df_ddos.to_csv("./pcap/2_csv.csv")
def clean(x):
	
	if(isinstance(x,float)):
		
		x=""
	if(x==np.nan):
		
		x=""
	x=x.replace('.',' ')
	entry_token=word_tokenize(x)
	
	stop_words = ['www','com','cn']	
	entry_list=[word for word in entry_token if word not in stop_words]
	x=""
	for word1 in entry_list:
		x=x+word1
	
	return x
def transform_qname(qname_col,qname_labels):
	col_name='qname.'+str(qname_col)
# 	global df_ddos or global train_x_df
	
	
	df_ddos[col_name]=df_ddos[col_name].map(clean)
	col_qname_df=df_ddos[col_name]
	col_qname_np=col_qname_df.values
	count_vectorizer = CountVectorizer(vocabulary=qname_labels,analyzer="char",ngram_range=(2,3),max_features=15)
	bag_of_words=count_vectorizer.fit_transform(col_qname_np)
	col_qname_array=bag_of_words.toarray()
	
	no_label=0
	for label in qname_labels:
		label1="qname"+str(qname_col)+"_"+label
		df_ddos.insert(40+2*qname_col+15*(qname_col-1),label1,col_qname_array[:,no_label])
		no_label=no_label+1
		label1=""

def transform_qname2(qname_col,qname_labels):
	col_name='qname.'+str(qname_col)
# 	global df_ddos or global train_x_df
	
	
	train_x_df[col_name]=train_x_df[col_name].map(clean)
	col_qname_df=train_x_df[col_name]
	col_qname_np=col_qname_df.values
	count_vectorizer = CountVectorizer(vocabulary=qname_labels,analyzer="char",ngram_range=(2,3),max_features=15)
	bag_of_words=count_vectorizer.fit_transform(col_qname_np)
	col_qname_array=bag_of_words.toarray()
	
	no_label=0
	for label in qname_labels:
		label1="qname"+str(qname_col)+"_"+label
		train_x_df.insert(40+2*qname_col+15*(qname_col-1),label1,col_qname_array[:,no_label])
		no_label=no_label+1
		label1=""

def cal_freq_pieces():
	df_1=pd.read_csv("./pcap/1_csv.csv")
	df_2=pd.read_csv("./pcap/2_csv.csv")
	df_3=pd.read_csv("./pcap/3_csv.csv")
	df_4=pd.concat([df_1,df_2,df_3])
	
	df_4=df_4.drop(['Unnamed: 0', 'Unnamed: 0.1', 'Unnamed: 0.1.1'],axis=1)
	df_4['qname']=df_4['qname'].apply(lambda x:clean(x))
	
	col_qname_df=df_4.iloc[:,25]
	col_qname_np=col_qname_df.values
	count_vectorizer = CountVectorizer(analyzer="char",ngram_range=(2,3),max_features=15)
	bag_of_words=count_vectorizer.fit_transform(col_qname_np)
	col_qname_array=bag_of_words.toarray()
	print(type(col_qname_array),col_qname_array.shape)
	qname_labels=count_vectorizer.get_feature_names()
	print(qname_labels)
def handle_datetime(x):
	y=datetime.fromisoformat(x)#error
	
	month=y.month
	return y	
def model():
	df_1=pd.read_csv("./pcap/1_csv.csv")
	df_2=pd.read_csv("./pcap/2_csv.csv")
	df_3=pd.read_csv("./pcap/3_csv.csv")
	df_4=pd.concat([df_1,df_2,df_3])
	#df_4.info()
	
	df_4=df_4.drop(['Unnamed: 0', 'Unnamed: 0.1', 'Unnamed: 0.1.1'],axis=1)
	
	index_train_ndarr=np.array(range(0,251188,4))
	index_train=index_train_ndarr.tolist()
	col_train=[]
	col_num=0
	while col_num<53:
		col_train.append(col_num)
		col_num=col_num+1
	col_num=54
	while col_num<63:
		col_train.append(col_num)
		col_num=col_num+1
	global train_x_df
	df_middle=df_4.iloc[index_train,:]
	df_middle=df_middle.replace([np.inf, -np.inf], 0)
	#print(col_train)
	
	train_x_df=df_middle.iloc[:,col_train]
	train_y_df=df_middle.iloc[:,53]
# 	train_y_df=train_y_df.fillna(1)
# 	train_y_df.to_csv("./pcap/train_y.csv")
	dict_y = {'index':train_y_df.index,'y':train_y_df.values}
	df_y = pd.DataFrame(dict_y)
	
	train_x_df['qname']=train_x_df['qname'].apply(lambda x:clean(x))
	train_x_df['dnstime']=train_x_df['dnstime'].apply(lambda x:handle_datetime(x))
	
	train_x_df['dnstime_month']=train_x_df['dnstime'].apply(lambda x:x.month)
	train_x_df['ethernettime']=train_x_df['ethernettime'].apply(lambda x:handle_datetime(x))
	
	train_x_df['ethernettime_month']=train_x_df['ethernettime'].apply(lambda x:x.month)
	col_qname_df=train_x_df.iloc[:,25]
	col_qname_np=col_qname_df.values
	count_vectorizer = CountVectorizer(analyzer="char",ngram_range=(2,3),max_features=15)
	bag_of_words=count_vectorizer.fit_transform(col_qname_np)
	col_qname_array=bag_of_words.toarray()
	qname_labels=count_vectorizer.get_feature_names()
	#print(qname_labels)
	no_label=0
	for label in qname_labels:
		label1="qname_"+label
		train_x_df.insert(25,label1,col_qname_array[:,no_label])
		no_label=no_label+1
		label1=""
	qname_col=1
	while qname_col<17:
		transform_qname2(qname_col,qname_labels)
		qname_col=qname_col+1
	train_x_df=train_x_df.drop(['dnstime','ethernettime'],axis=1)
	train_x_df=train_x_df.drop(['qname'],axis=1)
	qname_col_2=1
	while qname_col_2<17:
		new_label='qname.'+str(qname_col_2)
		
		train_x_df=train_x_df.drop([new_label],axis=1)
		qname_col_2=qname_col_2+1
	
	y_train=train_y_df.values
	train_x_df=train_x_df.replace([np.inf,-np.inf],0)
	train_x_df=train_x_df.fillna(0)
	test_null=np.isnan(train_x_df).any()
# 	test_null.to_csv("./pcap/null.csv")
	test_inf=np.isfinite(train_x_df).all()
	#train_x_df.info()
# 	test_inf.to_csv("./pcap/isfinite.csv")
	x_teach=train_x_df.values
	scaler = preprocessing.MinMaxScaler(feature_range=(0,1))
	standardized_x = scaler.fit_transform(x_teach)
# 	df_ut=pd.DataFrame(standardized_x,index=[i for i in range(0,18899)],columns=train_x_df.columns.values.tolist())
# 	df_ut.to_csv("./pcap/util.csv")
# 	standardized_x=np.nan_to_num(standardized_x)
# 	standardized_x[np.isinf(standardized_x)]=0
# 	print(np.where(np.isinf(standardized_x)))
# 	print(np.where(np.isnan(standardized_x)))
# 	
# 	train_x_df.to_csv("./pcap/train_df.csv")
	randomforest = RandomForestClassifier(random_state=0,n_jobs=-1)
	model = randomforest.fit(standardized_x,y_train)
	importances = model.feature_importances_
	indices = np.argsort(importances)[::-1]
	feature_names=train_x_df.columns.tolist()
	for i in feature_names:
		print(i)
	max_importance=importances.max()
# 	plt.figure()
# 	plt.title("Feature Importance") 
# 	plt.bar(range(0,len(feature_names),1), importances[indices])
# 	plt.xticks(range(0,len(feature_names),1), names, rotation=90,fontsize=3)
# 	plt.rcParams['figure.figsize'] = (16.0, 8.0)
# 	plt.rcParams['savefig.dpi'] = 500 #图片像素
# 	plt.rcParams['figure.dpi'] = 500 
# 	plt.show()-np.inf,max_features=140
	#print(max_importance)
	threshold = np.linspace(0,max_importance*0.15,num=50)
	#print(len(threshold),type(threshold))
	score = []
	for i in threshold:
		
		X_embedded = SelectFromModel(randomforest,threshold=i,prefit=True).transform(standardized_x)
		model = randomforest.fit(X_embedded,y_train)
		once = cross_val_score(randomforest,X_embedded,y_train,cv=5,scoring='accuracy').mean()
		
		score.append(once)
		randomforest = RandomForestClassifier(random_state=0,n_jobs=-1)
		model = randomforest.fit(standardized_x,y_train)
	plt.plot(threshold,score)
	
	plt.xticks(threshold, rotation=90,fontsize=4)
	plt.rcParams['figure.figsize'] = (16.0, 8.0)
	plt.rcParams['savefig.dpi'] = 500 #图片像素
	plt.rcParams['figure.dpi'] = 500 #分辨率
	plt.show()
	#print(threshold)
	joblib.dump(randomforest, 'D:\\dns\saved_model\\rfc_before.pkl')
	selector= SelectFromModel(randomforest,threshold=-np.inf,max_features=41,prefit=True)#0.00815
	importances = randomforest.feature_importances_ 
	indices = np.argsort(importances)[-41:]
	names=[]
	for i in range(41):
		curIndex=indices[i]
		names.append(feature_names[curIndex])
	
# 	for ent in names:
# 		print(ent)
	features_important = selector.transform(standardized_x)
	#print(type(features_important),features_important.shape)
	
# 	test_important_x=selector.transform(x_exam)
	model = randomforest.fit(features_important,y_train)
	#print((model.feature_importances_).max())
	
	cv_score=cross_val_score(randomforest,X_embedded,y_train,cv=5,scoring='accuracy').mean()
	#print(cv_score)
	#file_path = os.path.dirname(os.path.realpath(__file__))
	joblib.dump(randomforest, 'D:\\dns\saved_model\\rfc.pkl')

def json_to_what_can_be_fed_to_model():
	rfc2 = joblib.load('D:\\dns\saved_model\\rfc.pkl')
	#transform(src_hgc, dst_hgc)
	with open("D:/dns/pcap/testing.json","r",encoding="gbk")as fp:#使用时把testing.json换成你想要预测的json文件
		info=fp.read()
		raw=json.loads(info)
		data=raw["data"]
		df = pd.DataFrame.from_dict(json_normalize(data), orient='columns')
		df1=pd.DataFrame(df["queryarrs"].values.tolist())
		#df1.to_csv("./pcap/xxx.csv")
		#print(df1.shape[1],list(df1))
		len_df1=int(df1.shape[1]/3)
		#print(len_df1)
		for i in range(1):
			df3=df1[i].apply(pd.Series)
			df= pd.concat([df,df3],axis=1)
		df=df.drop(["queryarrs"],axis=1)
		
		df4=pd.DataFrame(df["answerarrs"].values.tolist())
# 		df4.to_csv("./pcap/wyt.csv")
		max_an=int(df4.shape[1])
		#print(max_an)
		#print("run to here")
		#print(df4.shape[1],list(df4))
		
		for i in range(16):
			df5=df4[i].apply(pd.Series)
			df= pd.concat([df,df5],axis=1)
		df=df.drop(["answerarrs"],axis=1)
		df=df.drop(["sensorid"],axis=1)
		df=df.drop(["sessionid"],axis=1)
		#df.to_csv("./pcap/qyq.csv")
# 		df.info()
		dict_test=dict(list(df.groupby('qr')))
		df_res=dict_test[1]
		df_req=dict_test[0]
		
		
		
		df_util=pd.read_csv("./pcap/util2.csv")
		df_util=df_util.drop(['Unnamed: 0'],axis=1)
		df_mid=pd.concat([df_req,df_res])
		df_mid.to_csv("./pcap/mid.csv")
		df_mid=pd.read_csv("./pcap/mid.csv")
		#print(list(df_mid))
		#print(list(df_util))
		global df_ddos
		df_ddos=pd.concat([df_mid,df_util]).reset_index(drop=True)
		#df_ddos.to_csv("./pcap/checklastone1.csv")
		df_ddos.drop([len(df_ddos)-1],inplace=True)
		#df_ddos.to_csv("./pcap/checklastone2.csv")
		df_ddos=df_ddos.drop(['Unnamed: 0'],axis=1)
		max_an_benign=16
		max_an_ddos=16
		#df_ddos.info()
		#print(df_ddos.columns.values.tolist())
		array_util=[1,28]
		for index, row in df_ddos.iterrows():
			for i,v in row.items():
				if i=='qtype.1':
					if np.isnan(v):
						df_ddos.loc[int(index),'answerIsNull']=1
						df_ddos.loc[int(index),'qtype.1']=array_util[random.randint(0,1)]
					else:
					
						df_ddos.loc[int(index),'answerIsNull']=0
					
							
				elif 'qtype.' in i:
					if np.isnan(v):
						df_ddos.loc[int(index),i]=array_util[random.randint(0,1)]
						#print('fill',index,i)
				elif 'rdlength' in i:
					if np.isnan(v):
						df_ddos.loc[int(index),i]=0
				elif 'ttl' in i:
					if np.isnan(v):
						df_ddos.loc[int(index),i]=0
				elif 'qname.' in i:
				
					if v is np.nan:
						df_ddos.loc[int(index),i]=''
		colist_1=['rdlength']
		for ii in range(1,max_an_ddos):
			rdlencol='rdlength.'+str(ii)
			colist_1.append(rdlencol)
		
		df_ddos['rdlength_avg']=df_ddos[colist_1].sum(axis=1)
		colist_2=['ttl']
	
		for dd in range(1,max_an_ddos):
			ttlcol='ttl.'+str(dd)
			rdatacol='rdata.'+str(dd)
			df_ddos=df_ddos.drop([rdatacol],axis=1)
			colist_2.append(ttlcol)
		
		df_ddos['ttl_avg']=df_ddos[colist_2].sum(axis=1)
		df_ddos=df_ddos.drop(colist_2,axis=1)
		df_ddos=df_ddos.drop(colist_1,axis=1)
		for index_qclass in range(1,max_an_ddos+1):
			qclasscol='qclass.'+str(index_qclass)
			df_ddos=df_ddos.drop([qclasscol],axis=1)
		df_ddos=df_ddos.drop(['qclass'],axis=1)
		df_ddos=df_ddos.drop(['src_s'],axis=1)
		df_ddos=df_ddos.drop(['dst_s'],axis=1)
		df_ddos=df_ddos.drop(['additionalarrs'],axis=1)
		df_ddos=df_ddos.drop(['authorityarrs'],axis=1)
		df_ddos=df_ddos.drop(['id'],axis=1)
		df_ddos=df_ddos.drop(['rdata'],axis=1)
		#df_ddos.info()
		df_ddos=df_ddos.replace([np.inf, -np.inf], 0)
		df_ddos['qname']=df_ddos['qname'].apply(lambda x:clean(x))
		df_ddos['dnstime']=df_ddos['dnstime'].apply(lambda x:handle_datetime(x))
		
		df_ddos['dnstime_month']=df_ddos['dnstime'].apply(lambda x:x.month)
		df_ddos['ethernettime']=df_ddos['ethernettime'].apply(lambda x:handle_datetime(x))
		df_ddos['ethernettime_month']=df_ddos['ethernettime'].apply(lambda x:x.month)
		col_qname_df=df_ddos.iloc[:,25]
		col_qname_np=col_qname_df.values
		count_vectorizer = CountVectorizer(vocabulary=['0e', '1a', '1a4', '4c', '4cc', 'a4', 'a4c', 'b0', 'b0e', 'cc', 'd1', 'd1a', 'dn', 'dns', 'ns'],ngram_range=(2,3))
		bag_of_words=count_vectorizer.fit_transform(col_qname_np)
		col_qname_array=bag_of_words.toarray()
		qname_labels=count_vectorizer.get_feature_names()
		#print(qname_labels)
		qname_labels=['0e', '1a', '1a4', '4c', '4cc', 'a4', 'a4c', 'b0', 'b0e', 'cc', 'd1', 'd1a', 'dn', 'dns', 'ns']
		#print(count_vectorizer.vocabulary_)
		no_label=0
		for label in qname_labels:
			label1="qname_"+label
			df_ddos.insert(25,label1,col_qname_array[:,no_label])
			no_label=no_label+1
			label1=""
		qname_col=1
		while qname_col<17:
			transform_qname(qname_col,qname_labels)
			qname_col=qname_col+1
		df_ddos=df_ddos.drop(['dnstime','ethernettime'],axis=1)
		df_ddos=df_ddos.drop(['qname'],axis=1)
		qname_col_2=1
		while qname_col_2<17:
			new_label='qname.'+str(qname_col_2)
			df_ddos=df_ddos.drop([new_label],axis=1)
			qname_col_2=qname_col_2+1
		df_ddos=df_ddos.replace([np.inf,-np.inf],0)
		df_ddos=df_ddos.fillna(0)
		df_ddos.to_csv("./pcap/real_csv.csv")
# 		test_null=np.isnan(train_x_df).any()
# # 	test_null.to_csv("./pcap/null.csv")
# 		test_inf=np.isfinite(train_x_df).all()
# # 	test_inf.to_csv("./pcap/isfinite.csv")
		x_unknown=df_ddos.values
		scaler = preprocessing.MinMaxScaler(feature_range=(0,1))
		standardized_x = scaler.fit_transform(x_unknown)
		rfc1=joblib.load("D:\\dns\saved_model\\rfc_before.pkl")
		selector= SelectFromModel(rfc1,threshold=-np.inf,max_features=41,prefit=True)#0.00815
		features_important = selector.transform(standardized_x)
		#print(type(features_important),features_important.shape)
		importances = rfc1.feature_importances_ 
		indices = np.argsort(importances)[-41:]
# 		feature_names=['aa','additionalnum','ancount','answernum','arcount','authoritynum','bytecnt','dport','nscount','opcode','pckcnt','protocol','ptype','qdcount','qr','querynum','ra','rcode','rd','sport','tc','transactionid','zero','qname_ns','qname_dns','qname_dn','qname_d1a','qname_d1','qname_cc','qname_b0e','qname_b0','qname_a4c','qname_a4','qname_4cc','qname_4c','qname_1a4','qname_1a','qname_0e','qtype','qname1_ns','qname1_dns','qname1_dn','qname1_d1a','qname1_d1','qname1_cc','qname1_b0e','qname1_b0','qname1_a4c','qname1_a4','qname1_4cc','qname1_4c','qname1_1a4','qname1_1a','qname1_0e','qtype.1','qname2_ns','qname2_dns','qname2_dn','qname2_d1a','qname2_d1','qname2_cc','qname2_b0e','qname2_b0','qname2_a4c','qname2_a4','qname2_4cc','qname2_4c','qname2_1a4','qname2_1a','qname2_0e','qtype.2','qname3_ns','qname3_dns','qname3_dn','qname3_d1a','qname3_d1','qname3_cc','qname3_b0e','qname3_b0','qname3_a4c','qname3_a4','qname3_4cc','qname3_4c','qname3_1a4','qname3_1a','qname3_0e','qtype.3','qname4_ns','qname4_dns','qname4_dn','qname4_d1a','qname4_d1','qname4_cc','qname4_b0e','qname4_b0','qname4_a4c','qname4_a4','qname4_4cc','qname4_4c','qname4_1a4','qname4_1a','qname4_0e','qtype.4','qname5_ns','qname5_dns','qname5_dn','qname5_d1a','qname5_d1','qname5_cc','qname5_b0e','qname5_b0','qname5_a4c','qname5_a4','qname5_4cc','qname5_4c','qname5_1a4','qname5_1a','qname5_0e','qtype.5','qname6_ns','qname6_dns','qname6_dn','qname6_d1a','qname6_d1','qname6_cc','qname6_b0e','qname6_b0','qname6_a4c','qname6_a4','qname6_4cc','qname6_4c','qname6_1a4','qname6_1a','qname6_0e','qtype.6','qname7_ns','qname7_dns','qname7_dn','qname7_d1a','qname7_d1','qname7_cc','qname7_b0e','qname7_b0','qname7_a4c','qname7_a4','qname7_4cc','qname7_4c','qname7_1a4','qname7_1a','qname7_0e','qtype.7','qname8_ns','qname8_dns','qname8_dn','qname8_d1a','qname8_d1','qname8_cc','qname8_b0e','qname8_b0','qname8_a4c','qname8_a4','qname8_4cc','qname8_4c','qname8_1a4','qname8_1a','qname8_0e','qtype.8','qname9_ns','qname9_dns','qname9_dn','qname9_d1a','qname9_d1','qname9_cc','qname9_b0e','qname9_b0','qname9_a4c','qname9_a4','qname9_4cc','qname9_4c','qname9_1a4','qname9_1a','qname9_0e','qtype.9','qname10_ns','qname10_dns','qname10_dn','qname10_d1a','qname10_d1','qname10_cc','qname10_b0e','qname10_b0','qname10_a4c','qname10_a4','qname10_4cc','qname10_4c','qname10_1a4','qname10_1a','qname10_0e','qtype.10','qname11_ns','qname11_dns','qname11_dn','qname11_d1a','qname11_d1','qname11_cc','qname11_b0e','qname11_b0','qname11_a4c','qname11_a4','qname11_4cc','qname11_4c','qname11_1a4','qname11_1a','qname11_0e','qtype.11','qname12_ns','qname12_dns','qname12_dn','qname12_d1a','qname12_d1','qname12_cc','qname12_b0e','qname12_b0','qname12_a4c','qname12_a4','qname12_4cc','qname12_4c','qname12_1a4','qname12_1a','qname12_0e','qtype.12','qname13_ns','qname13_dns','qname13_dn','qname13_d1a','qname13_d1','qname13_cc','qname13_b0e','qname13_b0','qname13_a4c','qname13_a4','qname13_4cc','qname13_4c','qname13_1a4','qname13_1a','qname13_0e','qtype.13','qname14_ns','qname14_dns','qname14_dn','qname14_d1a','qname14_d1','qname14_cc','qname14_b0e','qname14_b0','qname14_a4c','qname14_a4','qname14_4cc','qname14_4c','qname14_1a4','qname14_1a','qname14_0e','qtype.14','qname15_ns','qname15_dns','qname15_dn','qname15_d1a','qname15_d1','qname15_cc','qname15_b0e','qname15_b0','qname15_a4c','qname15_a4','qname15_4cc','qname15_4c','qname15_1a4','qname15_1a','qname15_0e','qtype.15','qname16_ns','qname16_dns','qname16_dn','qname16_d1a','qname16_d1','qname16_cc','qname16_b0e','qname16_b0','qname16_a4c','qname16_a4','qname16_4cc','qname16_4c','qname16_1a4','qname16_1a','qname16_0e','qtype.16','answerIsNull','rdlength_avg','ttl_avg','dnstime_month','ethernettime_month']
# 		names=[]
# 		for i in range(41):
#  			curIndex=indices[i]
#  			print(feature_names[curIndex])
		
		y_hat=rfc2.predict(features_important)
		
		ndarr_result=np.array(y_hat)
		
		df = pd.DataFrame(ndarr_result,columns = ["is_ddos"])
		df.to_csv("./pcap/predict_result.csv")
		
	
	
#transform(src_hgc, dst_hgc)
#json_to_dataframe()
# data_preprocessing()
#model()
# cal_freq_pieces(
json_to_what_can_be_fed_to_model()