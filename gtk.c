/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball
    Changes/additions Copyright (C) 1998 R.E.Wolff@BitWizard.nl

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <config.h>
#include <sys/time.h>

#ifndef NO_GTK
#include <stdlib.h>
#include <gtk/gtk.h>

#include "net.h"
#include "dns.h"
#include "mtr-gtk.h"

#include "img/mtr_icon.xpm"
#endif

extern char *Hostname;
extern float WaitTime;
extern float DeltaTime;

void gtk_do_init(int *argc, char ***argv) {
  static int done = 0;

  if(!done) {
    gtk_init(argc, argv);

    done = 1;
  }
}

int gtk_detect(int *argc, char ***argv) {
  if(getenv("DISPLAY") != NULL) {
    gtk_do_init(argc, argv);
    return TRUE;
  } else {
    return FALSE;
  }
}

gint Window_destroy(GtkWidget *Window, gpointer data) {
  gtk_main_quit();

  return FALSE;
}

gint Restart_clicked(GtkWidget *Button, gpointer data) {
  net_reset();
  gtk_redraw();

  return FALSE;
}

gint Host_activate(GtkWidget *Entry, gpointer data) {
  int addr;

  addr = dns_forward(gtk_entry_get_text(GTK_ENTRY(Entry)));
  if(addr)
    net_reopen(addr);

  return FALSE;
}

GdkPixmap *gtk_load_pixmap(char **pixmap) {
  return gdk_pixmap_colormap_create_from_xpm_d(NULL, 
					       gdk_colormap_get_system(), 
					       NULL, NULL, pixmap);
}

void Toolbar_fill(GtkWidget *Toolbar) {
  GtkWidget *Button;
  GtkWidget *Label;
  GtkWidget *Entry;

  Button = gtk_button_new_with_label("Quit");
  gtk_box_pack_end(GTK_BOX(Toolbar), Button, FALSE, FALSE, 0);
  gtk_signal_connect(GTK_OBJECT(Button), "clicked",
		     GTK_SIGNAL_FUNC(Window_destroy), NULL);
  gtk_widget_show(Button);

  Button = gtk_button_new_with_label("Restart");
  gtk_box_pack_end(GTK_BOX(Toolbar), Button, FALSE, FALSE, 0);
  gtk_signal_connect(GTK_OBJECT(Button), "clicked",
		     GTK_SIGNAL_FUNC(Restart_clicked), NULL);
  gtk_widget_show(Button);

  Label = gtk_label_new("Hostname");
  gtk_box_pack_start(GTK_BOX(Toolbar), Label, FALSE, FALSE, 0);
  gtk_widget_show(Label);

  Entry = gtk_entry_new();
  gtk_entry_set_text(GTK_ENTRY(Entry), Hostname);
  gtk_signal_connect(GTK_OBJECT(Entry), "activate",
		     GTK_SIGNAL_FUNC(Host_activate), NULL);
  gtk_box_pack_start(GTK_BOX(Toolbar), Entry, TRUE, TRUE, 0);
  gtk_widget_show(Entry);
}

char *Report_Text[] = { "Hostname", "Loss", "Rcv", "Snt", "Best", "Avg", "Worst", NULL };
int Report_Positions[] = { 10, 240, 280, 320, 360, 400, 440, 0 };
GtkWidget *Report;
GtkWidget *ReportBody;

GtkWidget *GetRow(int index) {
  int addr;
  char str[256], *name;
  GtkWidget *Row, *Label;

  Row = gtk_fixed_new();
  
  addr = net_addr(index);
  name = "???";
  if(addr != 0) {
    name = dns_lookup(addr);
    if(!name) {
      /* Actually this is not neccesary: 
	 dns_lookup always returns a printable string */
      name = strlongip (addr);
    }
  }

  Label = gtk_label_new(name);
  gtk_fixed_put(GTK_FIXED(Row), Label, Report_Positions[0], 0);
  gtk_widget_show(Label);

  return Row;
}

GtkWidget *Scrollarea_create() {
  GtkWidget *List;
  int count;

  for(count = 0; Report_Positions[count]; count++);

  List = GTK_WIDGET(gtk_clist_new_with_titles(count, Report_Text));
  gtk_clist_set_policy(GTK_CLIST(List), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  for(count = 0; Report_Positions[count + 1]; count++) {
    gtk_clist_set_column_width(GTK_CLIST(List), count, 
			       Report_Positions[count + 1] - 
			       Report_Positions[count]);
  }
  gtk_clist_set_column_width(GTK_CLIST(List), count, 0);
  for(count = 1; Report_Positions[count]; count++) {
    gtk_clist_set_column_justification(GTK_CLIST(List), count, GTK_JUSTIFY_RIGHT);
  }

  ReportBody = List;
  return List;
}

void gtk_add_row(GtkWidget *List) {
  int at;
  GtkWidget *Row, *Label;

  Row = gtk_fixed_new();
  
  for(at = 0; Report_Positions[at] != 0; at++) {
    Label = gtk_label_new("-");
    if(at) {
      gtk_widget_set_usize(Label, 40, 0);
      gtk_label_set_justify(GTK_LABEL(Label), GTK_JUSTIFY_RIGHT);
    }
    gtk_fixed_put(GTK_FIXED(Row), Label, Report_Positions[at], 0);
    gtk_widget_show(Label);
  }

  gtk_box_pack_start(GTK_BOX(List), Row, FALSE, FALSE, 0);
  gtk_widget_show(Row);
}

void gtk_set_field(GtkCList *List, int row, int ix, char *str) {
  gtk_clist_set_text(List, row, ix, str);
}

void gtk_set_field_num(GtkCList *List, int row, int ix, char *format, int num) {
  char str[32];

  sprintf(str, format, num);
  gtk_set_field(List, row, ix, str);
}

void gtk_update_row(GtkCList *List, int row) {
  int addr;
  char str[256], *name;

  addr = net_addr(row);
  name = "???";
  if(addr != 0) {
    name = dns_lookup(addr);
    if(!name) {
      sprintf(str, "%d.%d.%d.%d", (addr >> 24) & 0xff, (addr >> 16) & 0xff, 
	      (addr >> 8) & 0xff, addr & 0xff);
      name = str;
    }
  }
  gtk_set_field(List, row, 0, name);

  gtk_set_field_num(List, row, 1, "%d%%", net_percent(row));
  gtk_set_field_num(List, row, 2, "%d", net_returned(row));  
  gtk_set_field_num(List, row, 3, "%d", net_xmit(row));
  
  gtk_set_field_num(List, row, 4, "%d", net_best(row));
  gtk_set_field_num(List, row, 5, "%d", net_avg(row));  
  gtk_set_field_num(List, row, 6, "%d", net_worst(row));
  
}

void gtk_redraw() {
  int at;
  int max = net_max();

  gtk_clist_freeze(GTK_CLIST(ReportBody));

  while(GTK_CLIST(ReportBody)->rows < max) {
    gtk_clist_append(GTK_CLIST(ReportBody), Report_Text);
  }

  while(GTK_CLIST(ReportBody)->rows > max) {
    gtk_clist_remove(GTK_CLIST(ReportBody), GTK_CLIST(ReportBody)->rows - 1);
  }

  for(at = 0; at < max; at++) {
    gtk_update_row(GTK_CLIST(ReportBody), at);
  }

  gtk_clist_thaw(GTK_CLIST(ReportBody));
}

void Window_fill(GtkWidget *Window) {
  GtkWidget *VBox;
  GtkWidget *Toolbar;
  GtkWidget *List;

  gtk_window_set_title(GTK_WINDOW(Window), "My traceroute  [v" VERSION "]");
  gtk_widget_set_usize(Window, 540, 400); 
  gtk_container_border_width(GTK_CONTAINER(Window), 10);
  VBox = gtk_vbox_new(FALSE, 10);

  Toolbar = gtk_hbox_new(FALSE, 10);
  Toolbar_fill(Toolbar);
  gtk_box_pack_start(GTK_BOX(VBox), Toolbar, FALSE, FALSE, 0);
  gtk_widget_show(Toolbar);

  List = Scrollarea_create();
  gtk_box_pack_start(GTK_BOX(VBox), List, TRUE, TRUE, 0);
  gtk_widget_show(List);
  
  gtk_container_add(GTK_CONTAINER(Window), VBox);
  gtk_widget_show(VBox);
}

void gtk_open() {
  GtkWidget *Window;
  GdkPixmap *icon;

  int argc;
  char *args[2];
  char **argv;
  argc = 1;
  argv = args;
  argv[0] = "";
  argv[1] = NULL;
  gtk_do_init(&argc, &argv);

  Window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

  Window_fill(Window);

  gtk_signal_connect_object(GTK_OBJECT(Window), "delete_event",
			    GTK_SIGNAL_FUNC(gtk_widget_destroy), 
			    GTK_OBJECT(Window));
  gtk_signal_connect(GTK_OBJECT(Window), "destroy",
		     GTK_SIGNAL_FUNC(Window_destroy), NULL);

  icon = gtk_load_pixmap(mtr_icon);
  gtk_widget_show(Window);
  gdk_window_set_icon(Window->window, NULL, icon, NULL);
  gdk_window_set_icon_name(Window->window, "mtr");
}

void gtk_close() {
}

int gtk_keyaction() {
  return 0;
}

gint gtk_ping(gpointer data) {
  gtk_redraw();
  net_send_batch();
  return TRUE;
}

void gtk_net_data(gpointer data, gint fd, GdkInputCondition cond) {
  net_process_return();
}

void gtk_dns_data(gpointer data, gint fd, GdkInputCondition cond) {
  dns_ack();

  gtk_redraw();
}


void gtk_loop() {
  DeltaTime = WaitTime/10;
  gtk_timeout_add(DeltaTime*1000, gtk_ping, NULL);
  gdk_input_add(net_waitfd(), GDK_INPUT_READ, gtk_net_data, NULL);
  gdk_input_add(dns_waitfd(), GDK_INPUT_READ, gtk_dns_data, NULL);

  gtk_main();
}
