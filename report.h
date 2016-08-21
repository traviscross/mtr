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

/*  Prototypes for report.h  */

extern void report_open(void);
extern void report_close(void);
extern void txt_open(void);
extern void txt_close(void);
extern void json_open(void);
extern void json_close(void);
extern void xml_open(void);
extern void xml_close(void);
extern void csv_open(void);
extern void csv_close(time_t now);
