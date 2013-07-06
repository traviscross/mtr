/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

// The autoconf system provides us with the NO_IPINFO define. 
// Littering the code with #ifndef NO_IPINFO (double negative)
// does not benefit readabilty. So here we invert the sense of the
// define. 
//
// Similarly, this include file should be included unconditially. 
// It will evaluate to nothing if we don't need it. 

#ifndef NO_IPINFO
#define IPINFO


extern int ipinfo_no;
extern int ipinfo_max;
extern int iiwidth_len;
extern int iihash;
void asn_open();
void asn_close();
char *fmt_ipinfo(ip_t *addr);
int get_iiwidth(void);
int is_printii(void);

#endif
