SUBDIRS = bin config retrace plugins

interface_PYTHON = backtrace.wsgi \
                   create.wsgi \
                   checkpackage.wsgi \
                   delete.wsgi \
                   exploitable.wsgi \
                   index.wsgi \
                   log.wsgi \
                   manager.wsgi \
                   ftp.wsgi \
                   settings.wsgi \
                   start.wsgi \
                   stats.wsgi \
                   status.wsgi

interface_DATA = index.xhtml \
                 manager.xhtml \
                 manager_vmcore_task_form.xhtml \
                 manager_usrcore_task_form.xhtml \
                 managertask.xhtml \
                 stats.xhtml
# interfacedir should probably be $$(pkgdatadir)/retrace
interfacedir =  $(datadir)/retrace-server

EXTRA_DIST = $(interface_DATA)
