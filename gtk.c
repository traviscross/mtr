/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball
    Changes/additions Copyright (C) 1998 R.E.Wolff@BitWizard.nl

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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef HAVE_GTK
#include <string.h>
#include <sys/types.h>
#include <gtk/gtk.h>

#include "mtr.h"
#include "net.h"
#include "dns.h"
#include "asn.h"
#include "mtr-gtk.h"

#include "img/mtr_icon.xpm"
#endif

gint gtk_ping(gpointer data);
gint Copy_activate(GtkWidget *widget, gpointer data);
gint NewDestination_activate(GtkWidget *widget, gpointer data);
gboolean ReportTreeView_clicked(GtkWidget *Tree, GdkEventButton *event);
gchar* getSelectedHost(GtkTreePath *path);



extern char *Hostname;
extern float WaitTime;
extern int af;
static int ping_timeout_timer;
static GtkWidget *Pause_Button;
static GtkWidget *Entry;
static GtkWidget *main_window;

void gtk_add_ping_timeout (void)
{
  if(gtk_toggle_button_get_active((GtkToggleButton *)Pause_Button)){
    return;
  }
  int dt;
  dt = calc_deltatime (WaitTime);
  ping_timeout_timer = g_timeout_add(dt / 1000, gtk_ping, NULL);
}


void gtk_do_init(int *argc, char ***argv) 
{
  static int done = 0;

  if(!done) {
    gtk_init(argc, argv);

    done = 1;
  }
}


int gtk_detect(UNUSED int *argc, UNUSED char ***argv) 
{
  if(getenv("DISPLAY") != NULL) {
    /* If we do this here, gtk_init exits on an error. This happens
       BEFORE the user has had a chance to tell us not to use the 
       display... */
    return TRUE;
  } else {
    return FALSE;
  }
}


gint Window_destroy(UNUSED GtkWidget *Window, UNUSED gpointer data) 
{
  gtk_main_quit();

  return FALSE;
}


gint Restart_clicked(UNUSED GtkWidget *Button, UNUSED gpointer data) 
{
  net_reset();
  gtk_redraw();

  return FALSE;
}


gint Pause_clicked(UNUSED GtkWidget *Button, UNUSED gpointer data) 
{
  static int paused = 0;

  if (paused) {
    gtk_add_ping_timeout ();
  } else {
    g_source_remove (ping_timeout_timer);
  }
  paused = ! paused;
  gtk_redraw();

  return FALSE;
}

gint About_clicked(UNUSED GtkWidget *Button, UNUSED gpointer data) 
{
  gchar *authors[] = {
        "Matt Kimball <mkimball@xmission.com>",
        "Roger Wolff <R.E.Wolff@BitWizard.nl>",
        "Bohdan Vlasyuk <bohdan@cec.vstu.vinnica.ua>",
        "Evgeniy Tretyak <evtr@ukr.net>",
        "John Thacker <thacker@math.cornell.edu>",
        "Juha Takala",
        "David Sward <sward@clark.net>",
        "David Stone <stone@AsIf.com>",
        "Andrew Stesin",
        "Greg Stark <gsstark@mit.edu>",
        "Robert Sparks <rjsparks@nostrum.com>",
        "Mike Simons <msimons@moria.simons-clan.com>",
        "Aaron Scarisbrick,",
        "Craig Milo Rogers <Rogers@ISI.EDU>",
        "Antonio Querubin <tony@lavanauts.org>",
        "Russell Nelson <rn-mtr@crynwr.com>",
        "Davin Milun <milun@acm.org>",
        "Josh Martin <jmartin@columbiaservices.net>",
        "Alexander V. Lukyanov <lav@yars.free.net>",
        "Charles Levert <charles@comm.polymtl.ca> ",
        "Bertrand Leconte <B.Leconte@mail.dotcom.fr>",
        "Anand Kumria",
        "Olav Kvittem <Olav.Kvittem@uninett.no>",
        "Adam Kramer <l3zqc@qcunix1.acc.qc.edu> ",
        "Philip Kizer <pckizer@nostrum.com>",
        "Simon Kirby",
        "Christophe Kalt",
        "Steve Kann <stevek@spheara.horizonlive.com>",
        "Brett Johnson <brett@jdacareers.com>",
        "Roland Illig <roland.illig@gmx.de>",
        "Damian Gryski <dgryski@uwaterloo.ca>",
        "Rob Foehl <rwf@loonybin.net>",
        "Mircea Damian",
        "Cougar <cougar@random.ee>",
        "Travis Cross <tc@traviscross.com>",
        "Brian Casey",
        "Andrew Brown <atatat@atatdot.net>",
        "Bill Bogstad <bogstad@pobox.com> ",
        "Marc Bejarano <marc.bejarano@openwave.com>",
        "Moritz Barsnick <barsnick@gmx.net>",
        "Thomas Klausner <wiz@NetBSD.org>",
        NULL
    };
  
  gtk_show_about_dialog(GTK_WINDOW(main_window)
    , "version", PACKAGE_VERSION
    , "copyright", "Copyright \xc2\xa9 1997,1998  Matt Kimball"
    , "website", "http://www.bitwizard.nl/mtr/"
    , "authors", authors
    , "comments", "The 'traceroute' and 'ping' programs in a single network diagnostic tool."
    , "license",
"This program is free software; you can redistribute it and/or modify\n"
"it under the terms of the GNU General Public License version 2 as\n"
"published by the Free Software Foundation.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details."
  , NULL);
  return TRUE;
}

/*
 * There is a small problem with the following code:
 * The timeout is canceled and removed in order to ensure that
 * it takes effect (consider what happens if you set the timeout to 999,
 * then try to undo the change); is a better approach possible?
 *
 * What's the problem with this? (-> "I don't think so)
 */

gint WaitTime_changed(UNUSED GtkAdjustment *Adj, UNUSED GtkWidget *Button) 
{
  WaitTime = gtk_spin_button_get_value(GTK_SPIN_BUTTON(Button));
  g_source_remove (ping_timeout_timer);
  gtk_add_ping_timeout ();
  gtk_redraw();

  return FALSE;
}


gint Host_activate(GtkWidget *entry, UNUSED gpointer data) 
{
  struct hostent * addr;

  addr = dns_forward(gtk_entry_get_text(GTK_ENTRY(entry)));
  if(addr) {
    net_reopen(addr);
    /* If we are "Paused" at this point it is usually because someone
       entered a non-existing host. Therefore do the go-ahead... */
    gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( Pause_Button ) , 0);
  } else {
    int pos = strlen(gtk_entry_get_text( GTK_ENTRY(entry)));
    gtk_toggle_button_set_active( GTK_TOGGLE_BUTTON( Pause_Button ) , 1);
    gtk_editable_insert_text( GTK_EDITABLE(entry), ": not found", -1, &pos);
  }

  return FALSE;
}



void Toolbar_fill(GtkWidget *Toolbar) 
{
  GtkWidget *Button;
  GtkWidget *Label;
  GtkAdjustment *Adjustment;

  Button = gtk_button_new_from_stock(GTK_STOCK_QUIT);
  gtk_box_pack_end(GTK_BOX(Toolbar), Button, FALSE, FALSE, 0);
  g_signal_connect(GTK_OBJECT(Button), "clicked",
		     GTK_SIGNAL_FUNC(Window_destroy), NULL);

  Button = gtk_button_new_from_stock(GTK_STOCK_ABOUT);
  gtk_box_pack_end(GTK_BOX(Toolbar), Button, FALSE, FALSE, 0);
  g_signal_connect(GTK_OBJECT(Button), "clicked",
		     GTK_SIGNAL_FUNC(About_clicked), NULL);

  Button = gtk_button_new_with_mnemonic("_Restart");
  gtk_box_pack_end(GTK_BOX(Toolbar), Button, FALSE, FALSE, 0);
  g_signal_connect(GTK_OBJECT(Button), "clicked",
		     GTK_SIGNAL_FUNC(Restart_clicked), NULL);

  Pause_Button = gtk_toggle_button_new_with_mnemonic("_Pause");
  gtk_box_pack_end(GTK_BOX(Toolbar), Pause_Button, FALSE, FALSE, 0);
  g_signal_connect(GTK_OBJECT(Pause_Button), "clicked",
                    GTK_SIGNAL_FUNC(Pause_clicked), NULL);

  /* allow root only to set zero delay */
  Adjustment = (GtkAdjustment *)gtk_adjustment_new(WaitTime,
                                                  getuid()==0 ? 0.01:1.00,
                                                 999.99,
                                                  1.0, 10.0,
                                                  0.0);
  Button = gtk_spin_button_new(Adjustment, 0.5, 2);
  gtk_spin_button_set_numeric(GTK_SPIN_BUTTON(Button), TRUE);
  /* gtk_spin_button_set_snap_to_ticks(GTK_SPIN_BUTTON(Button), FALSE); */
  /* gtk_spin_button_set_set_update_policy(GTK_SPIN_BUTTON(Button),
     GTK_UPDATE_IF_VALID); */
  gtk_box_pack_end(GTK_BOX(Toolbar), Button, FALSE, FALSE, 0);
  g_signal_connect(GTK_OBJECT(Adjustment), "value_changed",
                    GTK_SIGNAL_FUNC(WaitTime_changed), Button);
 
  Label = gtk_label_new_with_mnemonic("_Hostname:");
  gtk_box_pack_start(GTK_BOX(Toolbar), Label, FALSE, FALSE, 0);

  Entry = gtk_entry_new();
  gtk_entry_set_text(GTK_ENTRY(Entry), Hostname);
  g_signal_connect(GTK_OBJECT(Entry), "activate",
		     GTK_SIGNAL_FUNC(Host_activate), NULL);
  gtk_box_pack_start(GTK_BOX(Toolbar), Entry, TRUE, TRUE, 0);
  
  gtk_label_set_mnemonic_widget(GTK_LABEL(Label), Entry);
}

static GtkWidget *ReportTreeView;
static GtkListStore *ReportStore;

enum {
#ifdef IPINFO
  COL_ASN,
#endif
  COL_HOSTNAME,
  COL_LOSS,
  COL_RCV,
  COL_SNT,
  COL_LAST,
  COL_BEST,
  COL_AVG,
  COL_WORST,
  COL_STDEV,
  COL_COLOR,
  N_COLS
};

// Trick to cast a pointer to integer.....
// We are mis-using a pointer as a single integer. On 64-bit
// architectures, the pointer is 64 bits and the integer only 32. 
// The compiler warns us of loss of precision. However we know we
// casted a normal 32-bit integer into this pointer a few microseconds
// earlier, so it is ok. Nothing to worry about....
#define POINTER_TO_INT(p) ((int)(long)(p))

void  float_formatter(GtkTreeViewColumn *tree_column UNUSED,
  GtkCellRenderer   *cell, 
  GtkTreeModel      *tree_model,
  GtkTreeIter       *iter, 
  gpointer           data)
{
  gfloat f;
  gchar text[64];
  gtk_tree_model_get(tree_model, iter, POINTER_TO_INT(data), &f, -1);
  sprintf(text, "%.2f", f);
  g_object_set(cell, "text", text, NULL);
}

void  percent_formatter(GtkTreeViewColumn *tree_column UNUSED,
  GtkCellRenderer   *cell, 
  GtkTreeModel      *tree_model,
  GtkTreeIter       *iter, 
  gpointer           data)
{
  gfloat f;
  gchar text[64];
  gtk_tree_model_get(tree_model, iter, POINTER_TO_INT(data), &f, -1);
  sprintf(text, "%.1f%%", f);
  g_object_set(cell, "text", text, NULL);
}

void TreeViewCreate(void)
{
  GtkCellRenderer *renderer;
  GtkTreeViewColumn *column;

  ReportStore = gtk_list_store_new(N_COLS,
#ifdef IPINFO
    G_TYPE_STRING,
#endif
    G_TYPE_STRING,
    G_TYPE_FLOAT,
    G_TYPE_INT,
    G_TYPE_INT,
    G_TYPE_INT,
    G_TYPE_INT,
    G_TYPE_INT,
    G_TYPE_INT,
    G_TYPE_FLOAT,
    G_TYPE_STRING
    );
    
  ReportTreeView = gtk_tree_view_new_with_model(GTK_TREE_MODEL(ReportStore));
  
  g_signal_connect(GTK_OBJECT(ReportTreeView), "button_press_event", 
  		    G_CALLBACK(ReportTreeView_clicked),NULL);

#ifdef IPINFO
  if (is_printii()) {
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("ASN",
      renderer,
      "text", COL_ASN,
      "foreground", COL_COLOR,
      NULL);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column (GTK_TREE_VIEW(ReportTreeView), column);
  }
#endif

  renderer = gtk_cell_renderer_text_new ();
  column = gtk_tree_view_column_new_with_attributes ("Hostname",
    renderer,
    "text", COL_HOSTNAME,
    "foreground", COL_COLOR,
    NULL);
  gtk_tree_view_column_set_expand(column, TRUE);
  gtk_tree_view_column_set_resizable(column, TRUE);
  gtk_tree_view_append_column (GTK_TREE_VIEW(ReportTreeView), column);

  renderer = gtk_cell_renderer_text_new ();
  g_object_set (G_OBJECT(renderer), "xalign", 1.0, NULL);
  column = gtk_tree_view_column_new_with_attributes ("Loss",
    renderer,
    "text", COL_LOSS,
    "foreground", COL_COLOR,
    NULL);
  gtk_tree_view_column_set_resizable(column, TRUE);
  gtk_tree_view_column_set_cell_data_func(column, renderer, percent_formatter, (void*)COL_LOSS, NULL);
  gtk_tree_view_append_column (GTK_TREE_VIEW(ReportTreeView), column);

  renderer = gtk_cell_renderer_text_new ();
  g_object_set (G_OBJECT(renderer), "xalign", 1.0, NULL);
  column = gtk_tree_view_column_new_with_attributes ("Snt",
    renderer,
    "text", COL_SNT,
    "foreground", COL_COLOR,
    NULL);
  gtk_tree_view_column_set_resizable(column, TRUE);
  gtk_tree_view_append_column (GTK_TREE_VIEW(ReportTreeView), column);

  renderer = gtk_cell_renderer_text_new ();
  g_object_set (G_OBJECT(renderer), "xalign", 1.0, NULL);
  column = gtk_tree_view_column_new_with_attributes ("Last",
    renderer,
    "text", COL_LAST,
    "foreground", COL_COLOR,
    NULL);
  gtk_tree_view_column_set_resizable(column, TRUE);
  gtk_tree_view_append_column (GTK_TREE_VIEW(ReportTreeView), column);

  renderer = gtk_cell_renderer_text_new ();
  g_object_set (G_OBJECT(renderer), "xalign", 1.0, NULL);
  column = gtk_tree_view_column_new_with_attributes ("Avg",
    renderer,
    "text", COL_AVG,
    "foreground", COL_COLOR,
    NULL);
  gtk_tree_view_column_set_resizable(column, TRUE);
  gtk_tree_view_append_column (GTK_TREE_VIEW(ReportTreeView), column);
  
  renderer = gtk_cell_renderer_text_new ();
  g_object_set (G_OBJECT(renderer), "xalign", 1.0, NULL);
  column = gtk_tree_view_column_new_with_attributes ("Best",
    renderer,
    "text", COL_BEST,
    "foreground", COL_COLOR,
    NULL);
  gtk_tree_view_column_set_resizable(column, TRUE);
  gtk_tree_view_append_column (GTK_TREE_VIEW(ReportTreeView), column);

    renderer = gtk_cell_renderer_text_new ();
  g_object_set (G_OBJECT(renderer), "xalign", 1.0, NULL);
  column = gtk_tree_view_column_new_with_attributes ("Worst",
    renderer,
    "text", COL_WORST,
    "foreground", COL_COLOR,
    NULL);
  gtk_tree_view_column_set_resizable(column, TRUE);
  gtk_tree_view_append_column (GTK_TREE_VIEW(ReportTreeView), column);

  renderer = gtk_cell_renderer_text_new ();
  g_object_set (G_OBJECT(renderer), "xalign", 1.0, NULL);
  column = gtk_tree_view_column_new_with_attributes ("StDev",
    renderer,
    "text", COL_STDEV,
    "foreground", COL_COLOR,
    NULL);
  gtk_tree_view_column_set_resizable(column, TRUE);
  gtk_tree_view_column_set_cell_data_func(column, renderer, float_formatter, (void*)COL_STDEV, NULL);
  gtk_tree_view_append_column (GTK_TREE_VIEW(ReportTreeView), column);

}

void update_tree_row(int row, GtkTreeIter *iter)
{
  ip_t *addr;
  char str[256]="???", *name=str;

  addr = net_addr(row);
  if (addrcmp( (void *) addr, (void *) &unspec_addr, af)) {
    if ((name = dns_lookup(addr))) {
      if (show_ips) {
        snprintf(str, sizeof(str), "%s (%s)", name, strlongip(addr));
        name = str;
      }
    } else name = strlongip(addr);
  }

  gtk_list_store_set(ReportStore, iter,
    COL_HOSTNAME, name,
    COL_LOSS, (float)(net_loss(row)/1000.0),

    COL_RCV, net_returned(row),
    COL_SNT, net_xmit(row),

    COL_LAST, net_last(row)/1000,
    COL_BEST, net_best(row)/1000,
    COL_AVG, net_avg(row)/1000,
    COL_WORST, net_worst(row)/1000,
    COL_STDEV, (float)(net_stdev(row)/1000.0),
    
    COL_COLOR, net_up(row) ? "black" : "red",

    -1);
#ifdef IPINFO
  if (is_printii())
    gtk_list_store_set(ReportStore, iter, COL_ASN, fmt_ipinfo(addr), -1);
#endif
}

void gtk_redraw(void)
{
  int max = net_max();
  
  GtkTreeIter iter;
  int row = net_min();
  gboolean valid;

  valid = gtk_tree_model_get_iter_first(GTK_TREE_MODEL(ReportStore), &iter);

  while(valid) {
    if(row < max) {
      update_tree_row(row++, &iter);
      valid = gtk_tree_model_iter_next(GTK_TREE_MODEL(ReportStore), &iter);
    } else {
      valid = gtk_list_store_remove(ReportStore, &iter);
    }
  }
  while(row < max) {
    gtk_list_store_append(ReportStore, &iter);
    update_tree_row(row++, &iter);
  }
}


void Window_fill(GtkWidget *Window) 
{
  GtkWidget *VBox;
  GtkWidget *Toolbar;
  GtkWidget *scroll;

  gtk_window_set_title(GTK_WINDOW(Window), "My traceroute");
  gtk_window_set_default_size(GTK_WINDOW(Window), 650, 400); 
  gtk_container_set_border_width(GTK_CONTAINER(Window), 10);
  VBox = gtk_vbox_new(FALSE, 10);

  Toolbar = gtk_hbox_new(FALSE, 10);
  Toolbar_fill(Toolbar);
  gtk_box_pack_start(GTK_BOX(VBox), Toolbar, FALSE, FALSE, 0);
  
  TreeViewCreate();
  scroll = gtk_scrolled_window_new(NULL, NULL);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scroll), GTK_SHADOW_IN);
  gtk_container_add(GTK_CONTAINER(scroll), ReportTreeView);
  gtk_box_pack_start(GTK_BOX(VBox), scroll, TRUE, TRUE, 0);

  gtk_container_add(GTK_CONTAINER(Window), VBox);
}


void gtk_open(void)
{
  GdkPixbuf *icon;

  int argc;
  char *args[2];
  char **argv;
  argc = 1;
  argv = args;
  argv[0] = "";
  argv[1] = NULL;
  gtk_do_init(&argc, &argv);

  icon = gdk_pixbuf_new_from_xpm_data((const char**)mtr_icon);
  gtk_window_set_default_icon(icon);

  main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  
  g_set_application_name("My traceroute");

  Window_fill(main_window);

  g_signal_connect(GTK_OBJECT(main_window), "delete_event",
                     GTK_SIGNAL_FUNC(Window_destroy), NULL);
  g_signal_connect(GTK_OBJECT(main_window), "destroy",
		     GTK_SIGNAL_FUNC(Window_destroy), NULL);

  gtk_widget_show_all(main_window);
}


void gtk_close(void)
{
}


int gtk_keyaction(void)
{
  return 0;
}


gint gtk_ping(UNUSED gpointer data) 
{
  gtk_redraw();
  net_send_batch();
  net_harvest_fds();
  g_source_remove (ping_timeout_timer);
  gtk_add_ping_timeout ();
  return TRUE;
}


gboolean gtk_net_data(UNUSED GIOChannel *channel, UNUSED GIOCondition cond, UNUSED gpointer data) 
{
  net_process_return();
  return TRUE;
}


gboolean gtk_dns_data(UNUSED GIOChannel *channel, UNUSED GIOCondition cond, UNUSED gpointer data)
{
  dns_ack();
  gtk_redraw();
  return TRUE;
}
#ifdef ENABLE_IPV6
gboolean gtk_dns_data6(UNUSED GIOChannel *channel, UNUSED GIOCondition cond, UNUSED gpointer data)
{
  dns_ack6();
  gtk_redraw();
  return TRUE;
}
#endif


void gtk_loop(void) 
{
  GIOChannel *net_iochannel, *dns_iochannel;

  gtk_add_ping_timeout ();
  
  net_iochannel = g_io_channel_unix_new(net_waitfd());
  g_io_add_watch(net_iochannel, G_IO_IN, gtk_net_data, NULL);
#ifdef ENABLE_IPV6
  if (dns_waitfd6() > 0) {
    dns_iochannel = g_io_channel_unix_new(dns_waitfd6());
    g_io_add_watch(dns_iochannel, G_IO_IN, gtk_dns_data6, NULL);
  }
#endif
  dns_iochannel = g_io_channel_unix_new(dns_waitfd());
  g_io_add_watch(dns_iochannel, G_IO_IN, gtk_dns_data, NULL);

  gtk_main();
}

gboolean NewDestination_activate(GtkWidget *widget UNUSED, gpointer data)
{
  gchar *hostname;
  GtkTreePath *path = (GtkTreePath*)data;
	
  hostname = getSelectedHost(path);
  if (hostname) {
    gtk_entry_set_text (GTK_ENTRY(Entry), hostname);
    Host_activate(Entry, NULL);
    g_free(hostname);
  }
  return TRUE;
}


gboolean Copy_activate(GtkWidget *widget UNUSED, gpointer data)
{
  gchar *hostname;
  GtkTreePath *path = (GtkTreePath*)data;
	
  hostname = getSelectedHost(path);
  if (hostname != NULL) {
    GtkClipboard *clipboard;

    clipboard = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(clipboard, hostname, -1);

    clipboard = gtk_clipboard_get(GDK_SELECTION_PRIMARY);
    gtk_clipboard_set_text(clipboard, hostname, -1);

    g_free(hostname);
  }

  return TRUE;
}

gchar *getSelectedHost(GtkTreePath *path)
{
  GtkTreeIter iter;
  gchar *name = NULL;

  if (gtk_tree_model_get_iter(GTK_TREE_MODEL(ReportStore), &iter, path)) {
    gtk_tree_model_get (GTK_TREE_MODEL(ReportStore), &iter, COL_HOSTNAME, &name, -1);
  }
  gtk_tree_path_free(path);
  return name;
}


gboolean ReportTreeView_clicked(GtkWidget *Tree UNUSED, GdkEventButton *event)
{
  GtkWidget* popup_menu; 
  GtkWidget* copy_item; 
  GtkWidget* newdestination_item;
  GtkTreePath *path;

  if (event->type != GDK_BUTTON_PRESS  || event->button != 3)
    return FALSE;

  if(!gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(ReportTreeView),
      event->x, event->y, &path, NULL, NULL, NULL))
    return FALSE;
  
  gtk_tree_view_set_cursor(GTK_TREE_VIEW(ReportTreeView), path, NULL, FALSE);

  // Single right click: prepare and show the popup menu
  popup_menu = gtk_menu_new ();

  copy_item = gtk_menu_item_new_with_label ("Copy to clipboard");
  newdestination_item = gtk_menu_item_new_with_label ("Set as new destination"); 

  gtk_menu_append (GTK_MENU (popup_menu), copy_item); 
  gtk_menu_append (GTK_MENU (popup_menu), newdestination_item); 

  g_signal_connect(GTK_OBJECT(copy_item),"activate",
                   GTK_SIGNAL_FUNC(Copy_activate), path);

  g_signal_connect(GTK_OBJECT(newdestination_item),"activate",
                   GTK_SIGNAL_FUNC(NewDestination_activate), path);
              
  gtk_widget_show (copy_item); 
  gtk_widget_show (newdestination_item); 

  gtk_menu_popup (GTK_MENU(popup_menu), NULL, NULL, NULL, NULL,
                   0, event->time);
  return TRUE;
}

