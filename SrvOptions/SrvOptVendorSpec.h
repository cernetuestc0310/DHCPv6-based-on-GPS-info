/*
 * Dibbler - a portable DHCPv6
 *
 * authors: Tomasz Mrugalski <thomson@klub.com.pl>
 *          Marek Senderski <msend@o2.pl>
 *
 * released under GNU GPL v2 only licence
 *
 * $Log: SrvOptVendorSpec.h,v $
 * Revision 1.2  2008-08-29 00:07:38  thomson
 * Temporary license change(GPLv2 or later -> GPLv2 only)
 *
 * Revision 1.1  2006-11-03 20:07:07  thomson
 * Server-side vendorSpecInfo support added.
 *
 */

#ifndef SRVOPTVENDORSPECINFO_H
#define SRVOPTVENDORSPECINFO_H

#include "OptVendorSpecInfo.h"
#include "DHCPConst.h"

class TSrvOptVendorSpec : public TOptVendorSpecInfo
{
 public:
    TSrvOptVendorSpec(int enterprise, char * data, int dataLen, TMsg* parent);
    TSrvOptVendorSpec(char * buf,  int n, TMsg* parent);
    bool doDuties();
};

#endif /* VENDORSPECINFO_H_HEADER_INCLUDED_C1123F31 */
