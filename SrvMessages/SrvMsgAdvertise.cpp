/*                                                                           
* Dibbler - a portable DHCPv6                                               
*                                                                           
* authors: Tomasz Mrugalski <thomson@klub.com.pl>                           
*          Marek Senderski <msend@o2.pl>                                    
* changes: Michal Kowalczuk <michal@kowalczuk.eu>
*                                                                           
* released under GNU GPL v2 only licence                                
*                                                                           
* $Id: SrvMsgAdvertise.cpp,v 1.33 2008-11-13 22:40:26 thomson Exp $
*/

#include "SrvMsgAdvertise.h"
#include "Logger.h"
#include "SrvOptOptionRequest.h"
#include "SrvOptClientIdentifier.h"
#include "SrvOptIA_NA.h"
#include "SrvOptTA.h"
#include "SrvOptServerUnicast.h"
#include "SrvOptStatusCode.h"
#include "SrvOptServerIdentifier.h"
#include "SrvOptPreference.h"
#include "SrvOptDNSServers.h"
#include "SrvOptNTPServers.h"
#include "SrvOptTimeZone.h"
#include "SrvOptDomainName.h"
#include "SrvOptFQDN.h"
#include "SrvOptIA_PD.h"
#include "Logger.h"
#include "fstream"
#include "string.h"
#include "iostream"
#include "algorithm"
#include "vector"
using namespace std;
std::string ipv6_type, ipv6_addr;
std::string ipv6_addr2;
std::string Dec2Bin(int n)
{
	std::string tmp;
	for (int a = n; a; a = a / 2)
	{
		tmp = tmp + (a % 2 ? '1' : '0');
	}
	// 如何利用 reverse方法！！！！！！(已解决)加入algorithm 头文件 调用stl
	reverse(tmp.begin(), tmp.end());
	return tmp;
}

//函数作用：将二进制字符串转十进制
int Bin2Dec(std::string src)
{
	int tmp=0;
	int n = src.size();
	int k = 1;
	int i = 0;
	for (i = n - 1; i >= 0; i--)
	{
		tmp = tmp + (src[i] - '0')*k;
		k = k * 2;
	}


	return tmp;
}
//函数作用：将十进制转十六进制字符串
std:: string Dec2Hex(int n)
{
	std::string tmp;
	char str[20];
	sprintf(str, "%x", n);
	tmp = str;
	return tmp;
}

TSrvMsgAdvertise::TSrvMsgAdvertise(SmartPtr<TSrvIfaceMgr> IfaceMgr,
								   SmartPtr<TSrvTransMgr> TransMgr,
								   SmartPtr<TSrvCfgMgr> CfgMgr,
								   SmartPtr<TSrvAddrMgr> AddrMgr,
								   SmartPtr<TSrvMsgSolicit> solicit)
								   :TSrvMsg(IfaceMgr,TransMgr,CfgMgr,AddrMgr,
								   solicit->getIface(),solicit->getAddr(), ADVERTISE_MSG, 
								   solicit->getTransID())
{
	this->copyRelayInfo((Ptr*)solicit);
#ifndef MOD_DISABLE_AUTH
	this->copyAAASPI((Ptr*)solicit);
#endif
	this->copyRemoteID((Ptr*)solicit);
	if (!this->answer(solicit)) {
		this->IsDone = true;
		return;
	}
	this->IsDone = false;
}

bool TSrvMsgAdvertise::answer(SmartPtr<TSrvMsgSolicit> solicit) {
	SmartPtr<TOpt>       opt;
	SmartPtr<TSrvOptClientIdentifier> optClntID;
	SmartPtr<TDUID>      clntDuid;
	SmartPtr<TIPv6Addr>  clntAddr;
	unsigned int         clntIface;
	bool ia_flag=true;

	opt = solicit->getOption(OPTION_CLIENTID);
	optClntID = (Ptr*) opt;
	clntDuid = optClntID->getDUID();
	clntAddr = solicit->getAddr();
	clntIface =solicit->getIface();

#ifndef MOD_DISABLE_AUTH
	this->copyAAASPI((Ptr*)solicit);
#endif
	this->copyRemoteID((Ptr*)solicit);

	// is this client supported?
	if (!SrvCfgMgr->isClntSupported(clntDuid, clntAddr, clntIface)) {
		//No reply for this client 
		Log(Notice) << "Client (DUID=" << clntDuid->getPlain() << ",addr=" << *clntAddr 
			<< ") was rejected due to accept-only or reject-client." << LogEnd;
		return false;
	}

	SmartPtr<TSrvOptOptionRequest> reqOpts;

	//remember requested option in order to add number of "hint" options,
	//wich are included in this packet (but not in OPTION REQUEST option).
	//if OPTION REQUEST option wasn't included by client - create new one
	reqOpts= (Ptr*) solicit->getOption(OPTION_ORO);
	if (!reqOpts)
		reqOpts=new TSrvOptOptionRequest(this);

	// --- process this message ---
	solicit->firstOption();
	while ( opt = solicit->getOption()) {
		switch (opt->getOptType()) {
	case OPTION_CLIENTID : {
		this->Options.append(opt);
		break;
						   }

	case OPTION_IA_TA: {
		SmartPtr<TSrvOptTA> optTA;
		optTA = new TSrvOptTA(SrvAddrMgr, SrvCfgMgr, (Ptr*) opt, 
			clntDuid, clntAddr, clntIface, SOLICIT_MSG, this);
		this->Options.append( (Ptr*) optTA);
		break;
					   }
	case OPTION_IA_PD: {
		SmartPtr<TSrvOptIA_PD> optPD;
		optPD = new TSrvOptIA_PD(SrvCfgMgr, SrvAddrMgr, (Ptr*) opt, clntAddr, clntDuid,  
			clntIface, SOLICIT_MSG, this);
		this->Options.append( (Ptr*) optPD);
		break;
					   }
	case OPTION_RAPID_COMMIT: {
		// RAPID COMMIT present, but we're in ADVERTISE, so obviously
		// server is configured not to use RAPID COMMIT
		Log(Notice) << "Generating ADVERTISE message, RAPID COMMIT option ignored." << LogEnd;
		break;
							  }
	case OPTION_IAADDR: {
		Log(Warning) << "Invalid(misplaced) IAADDR option received." << LogEnd;
		break;
						}
	case OPTION_IAPREFIX: {
		Log(Warning) << "Invalid(misplaced) IAPREFIX option received." << LogEnd;
		break;
						  }
	case OPTION_AUTH : {
		reqOpts->addOption(OPTION_AUTH);
		break;
					   }                 
	case OPTION_ORO: 
	case OPTION_ELAPSED_TIME : {
		break;
							   }
	case OPTION_STATUS_CODE : {
		SmartPtr< TOptStatusCode > ptrStatus = (Ptr*) opt;
		Log(Error) << "Received STATUS_CODE from client:" 
			<<  ptrStatus->getCode() << ", (" << ptrStatus->getText()
			<< ")" << LogEnd;
		break;
							  }

							  //add options requested by client to option Request Option if
							  //client didn't included them

	case OPTION_DNS_SERVERS: {
		if (!reqOpts->isOption(OPTION_DNS_SERVERS))
			reqOpts->addOption(OPTION_DNS_SERVERS);
		break;
							 }
	case OPTION_DOMAIN_LIST: {
		if (!reqOpts->isOption(OPTION_DOMAIN_LIST))
			reqOpts->addOption(OPTION_DOMAIN_LIST);
		break;
							 }
	case OPTION_SNTP_SERVERS:
		if (!reqOpts->isOption(OPTION_SNTP_SERVERS))
			reqOpts->addOption(OPTION_SNTP_SERVERS);
		break;
	case OPTION_NEW_TZDB_TIMEZONE:
		if (!reqOpts->isOption(OPTION_NEW_TZDB_TIMEZONE))
			reqOpts->addOption(OPTION_NEW_TZDB_TIMEZONE);
		break;

	case OPTION_PREFERENCE :
	case OPTION_UNICAST :
	case OPTION_SERVERID : {
		Log(Warning) << "Invalid option (OPTION_UNICAST) received." << LogEnd;
		break;
						   }
	case OPTION_FQDN : {
		SmartPtr<TSrvOptFQDN> requestFQDN = (Ptr*) opt;
		SmartPtr<TOptFQDN> anotherFQDN = (Ptr*) opt;
		string hint = anotherFQDN->getFQDN();
		SmartPtr<TSrvOptFQDN> optFQDN;

		SPtr<TIPv6Addr> clntAssignedAddr = SrvAddrMgr->getFirstAddr(clntDuid);
		if (clntAssignedAddr)
			optFQDN = this->prepareFQDN(requestFQDN, clntDuid, clntAssignedAddr, hint, false);
		else
			optFQDN = this->prepareFQDN(requestFQDN, clntDuid, clntAddr, hint, false);

		if (optFQDN) {
			this->Options.append((Ptr*) optFQDN);
		}
		break;
					   }
					   //添加处理vendor 代码	
	case OPTION_VENDOR_OPTS:
		{
			SPtr<TSrvOptVendorSpec> v = (Ptr*) opt;
			appendVendorSpec(clntDuid, clntIface, v->getVendor(), reqOpts);
			//----------添加处理，利用gps数据生成ip地址的  host部分（后64位）-----处理gps-----
			std::string vendor=v->getVendorDataPlain();
			std::string vendor_type, vendor_len, 
				vendor_x, vendor_y, vendor_z;
			if(0==vendor.find("0x")){
				vendor=vendor.substr(2,vendor.length()-2);
			}
			vendor_type = vendor.substr(0, 4);
			vendor_len = vendor.substr(4, 4);
			vendor_x = vendor.substr(8, 9);
			vendor_y = vendor.substr(17, 9);
			vendor_z = vendor.substr(26, 6);

			std::string type2clntaddr=clntAddr->getPlain();

			// HSD  2017-06-13 -------IPv6本地链路地址到MAC的转换-------
			string mac_add = "00:00:00:00:00:00";
			string ip_add = type2clntaddr;
			size_t pos = ip_add.length() - 1;
			int count = 0, i = pos, temp = 0;
			if(':' != ip_add[ip_add.length() - 1]){
				count = 2;		
			}
			else{
				count = 3;
			}
			for(; i > 0; i--){
				if(':' == ip_add[i]){
					temp++;
					if( count == temp){
						break;
					}
				}
			}
			pos = i;
			int a = pos + 3;
			int ipt = 9;
			for(; a < ip_add.length(); a++){
				if(':' != ip_add[a]){
					if( ':' != mac_add[ipt]){
						mac_add[ipt++] = ip_add[a];
					}
					else{
						mac_add[++ipt] = ip_add[a];
						ipt++;
					}
				}
			}
			ipt = 7;
			a = pos - 3;
			for(; a > 5; a--){
				if(':' != ip_add[a]){
					if( ':' != mac_add[ipt]){
						mac_add[ipt--] = ip_add[a];
					}
					else{
						mac_add[--ipt] = ip_add[a];
						ipt--;
					}
				}
			}
			int b = 0;
			if('a'<= mac_add[1]){
				b = 10 + mac_add[1] - 'a';
			}
			else{
				b = mac_add[1] - '0';
			}
			b = b ^ 2;
			if(b < 10){
				mac_add[1] = '0' + b;
			}
			else{
				mac_add[1] = 'a' + b - 10;
			}
			type2clntaddr=mac_add;
			//-----------------------------------------------------------
			if(vendor_type=="0002")
			{

				ifstream fin1("/var/lib/dibbler/cfgdata/srv/maclist.txt");	
				ifstream fin2("/var/lib/dibbler/cfgdata/srv/gpslist.txt");     //2016-11-07
				if (!fin1||!fin2){
					//cout << "ipv6文件列表不存在" << endl;;
					//exit(1); // terminate with error 
					ipv6_addr2="-1";
				}
				vector<string> vc1, vc2;
				std::string s;
				while (!fin1.eof())
				{
					getline(fin1, s);
					//cout << s << endl;
					//------HSD  2017-06-13---大小写转换--------------
					for(int idx = 0; i < s.length(); i++){
						if(('A' <= s[i]) && (s[i] <= 'F')){
							s[i] = 'a' + s[i] - 'A';
						}
					}
					//------------------------------------------------
					vc1.push_back(s);

				}
				while (!fin2.eof())
				{
					getline(fin2, s);
					//cout << s << endl;
					vc2.push_back(s);
				}

				fin1.close();fin2.close();
				std::vector<string>:: iterator it1;
				it1=find(vc1.begin(),vc1.end(),type2clntaddr);
				if(it1==vc1.end())
				{
					ipv6_addr2="-1";
				}

				else
				{
					int a=0;
					a=it1-vc1.begin();

					vendor = vc2[a];
					vendor_x = vendor.substr(0, 9);
					vendor_y = vendor.substr(9, 9);
					vendor_z = vendor.substr(18, 6);
				}
			}


			std::string vendor_xx = vendor_x.substr(3, 6);
			std::string vendor_yy = vendor_y.substr(3, 6);
			int  gps_x, gps_y ,gps_zz;
			// double gps_z;
			gps_x = atoi(vendor_xx.c_str());
			gps_y = atoi(vendor_yy.c_str());
			gps_zz = atoi(vendor_z.c_str());
			// gps_z = ((double)gps_zz )/ 100;
			//--************************** gps 的经纬度和高度已经转为int类型
			std::string x_bin, y_bin, z_bin;
			x_bin = Dec2Bin(gps_x);
			//int xxx = Bin2Dec(x_bin);
			y_bin = Dec2Bin(gps_y);
			z_bin = Dec2Bin(gps_zz);

			std::string x_hex;
			x_hex = Dec2Hex(gps_x);

			for (int i = x_hex.size(); i < 5; i++)
			{

				x_hex =  '0'+ x_hex;

			}


			//**************纬度处理*****************
			std::string y_hex;
			y_hex = Dec2Hex(gps_y);
			for (int i = y_hex.size(); i < 5; i++)
			{

				y_hex = '0' + y_hex;

			}
			std::string z_hex;
			z_hex = Dec2Hex(gps_zz);
			for (int i = z_hex.size(); i < 5; i++)
			{

				z_hex = '0' + z_hex;

			}


			ipv6_type = "1";
			ipv6_addr = ipv6_type + x_hex + y_hex + z_hex;


			for (int k = 0; k < ipv6_addr.size(); k++)
			{
				ipv6_addr2 += ipv6_addr[k];
				if (((k +1)% 4 == 0)&&(k!=0)&&(k!=ipv6_addr.size()-1))
				{
					ipv6_addr2 = ipv6_addr2 + ":";
				}

			}


			//测试host id 是否正确
			//char filename3[]="/home/b1305/ip_host.txt";
			//ofstream fout3(filename3);
			//fout3<<"addr: "<<ipv6_addr<<endl;  
			//fout3<<"addr2: "<<ipv6_addr2<<endl;  
			//fout3<<"已经生成host -id..."<<endl;
			//fout3.close(); 




			//------------------------------end---------------------------------------------
			/*
			SmartPtr<TSrvOptIA_NA> optIA_NA;
			optIA_NA = new TSrvOptIA_NA(SrvAddrMgr, SrvCfgMgr, (Ptr*) opt,
			clntDuid, clntAddr, 
			clntIface, SOLICIT_MSG,this);
			this->Options.append((Ptr*)optIA_NA);
			*/
			//fout3<<"调用 ia_na +gps_info 完毕..."<<endl;



			/*
			char filename[]="/home/b1305/vendor_spec.txt";
			ofstream fout(filename);
			fout<<"v->getVendor():"<<v->getVendor()<<endl;  
			fout<<"v->getVendorDataPlain():"<<v->getVendorDataPlain()<<endl; 
			fout<<"v->getVendorDataLen():"<<v->getVendorDataLen()<<endl; 
			std::string vendor1=v->getVendorDataPlain();
			unsigned long long  num=0;
			num=atoi(vendor1.c_str());
			fout<<num<<endl;
			fout<<num+1<<endl;

			fout.close();  
			*/


			//Log(Notice) << "server get client vendor...hahaha..." << LogEnd;


			break;
		}
	case OPTION_IA_NA : {


		SmartPtr<TSrvOptIA_NA> optIA_NA;
		if(ipv6_addr2!="")
		{
			optIA_NA = new TSrvOptIA_NA(SrvAddrMgr, SrvCfgMgr, (Ptr*) opt,
				clntDuid, clntAddr, 
				clntIface, SOLICIT_MSG,this, ipv6_addr2);
			this->Options.append((Ptr*)optIA_NA);
		}

		break;
						}
	case OPTION_AAAAUTH:
		{
			Log(Debug) << "Auth: Option AAAAuthentication received." << LogEnd;
			break;
		}

		// options not yet supported 
	case OPTION_RELAY_MSG :
	case OPTION_USER_CLASS :
	case OPTION_VENDOR_CLASS:
	case OPTION_INTERFACE_ID :
	case OPTION_RECONF_MSG :
	case OPTION_RECONF_ACCEPT:
	default: {
		Log(Debug) << "Option " << opt->getOptType() << " is not supported." << LogEnd;
		break;
			 }
		} // end of switch
	} // end of while

	//if client requested parameters and policy doesn't forbid from answering
	this->appendRequestedOptions(clntDuid, clntAddr, clntIface, reqOpts);

	appendStatusCode();

	// include our DUID
	SmartPtr<TSrvOptServerIdentifier> ptrSrvID;
	ptrSrvID = new TSrvOptServerIdentifier(SrvCfgMgr->getDUID(),this);
	Options.append((Ptr*)ptrSrvID);

	// ... and our preference
	SmartPtr<TSrvOptPreference> ptrPreference;
	unsigned char preference = SrvCfgMgr->getIfaceByID(solicit->getIface())->getPreference();
	Log(Debug) << "Preference set to " << (int)preference << "." << LogEnd;
	ptrPreference = new TSrvOptPreference(preference,this);
	Options.append((Ptr*)ptrPreference);

	// does this server support unicast?
	SmartPtr<TIPv6Addr> unicastAddr = SrvCfgMgr->getIfaceByID(solicit->getIface())->getUnicast();
	if (unicastAddr) {
		SmartPtr<TSrvOptServerUnicast> optUnicast = new TSrvOptServerUnicast(unicastAddr, this);
		Options.append((Ptr*)optUnicast);
	}

	// this is ADVERTISE only, so we need to release assigned addresses
	this->firstOption();
	while ( opt = this->getOption()) {
		switch (opt->getOptType()) {
	case OPTION_IA_NA: {
		SmartPtr<TSrvOptIA_NA> ptrOptIA_NA;
		ptrOptIA_NA = (Ptr*) opt;
		ptrOptIA_NA->releaseAllAddrs(false);
		break;
					   }
	case OPTION_IA_TA: {
		SmartPtr<TSrvOptTA> ta;
		ta = (Ptr*) opt;
		ta->releaseAllAddrs(false);
		break;
					   }
	default:
		break;
		}
	}

	appendAuthenticationOption(clntDuid);

	pkt = new char[this->getSize()];
	this->MRT = 0;
	this->send();
	return true;
}

bool TSrvMsgAdvertise::check() {
	// this should never happen
	return true;
}

TSrvMsgAdvertise::~TSrvMsgAdvertise() {
}

unsigned long TSrvMsgAdvertise::getTimeout() {
	return 0;
}
void TSrvMsgAdvertise::doDuties() {
	IsDone = true;
}

string TSrvMsgAdvertise::getName() {
	return "ADVERTISE";
}
