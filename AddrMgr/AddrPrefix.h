/*
 * Dibbler - a portable DHCPv6
 *
 * author: Krzysztof Wnuk <keczi@poczta.onet.pl>
 *
 * $Log: AddrPrefix.h,v $
 * Revision 1.1  2006-10-06 00:30:17  thomson
 * Initial PD support.
 *
 * Revision 1.5  2006-08-03 00:43:15  thomson
 * FQDN support added.
 *
 * Revision 1.4  2004-06-20 19:36:46  thomson
 * Minor fixes.
 *
 */

#ifndef ADDRPREFIX_H
#define ADDRPREFIX_H

#include <iostream>
#include "IPv6Addr.h"
#include "AddrAddr.h"
#include "SmartPtr.h"
#include "DHCPConst.h"

using namespace std;

class TAddrPrefix: public TAddrAddr
{
    friend ostream & operator<<(ostream & strum,TAddrPrefix &x);
  public:

    TAddrPrefix(SmartPtr<TIPv6Addr> addr, long pref, long valid, int length);

    // return address in packed format (char[16])
    int getLength();

  private:
    int Length;
};
#endif
