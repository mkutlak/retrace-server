MAN_TXT = \
    retrace-server-cleanup.txt \
    retrace-server-interact.txt \
    retrace-server-reposync.txt \
    retrace-server-task.txt \
    retrace-server-worker.txt

#Manual pages are generated from .txt via Docbook
man1_MANS = ${MAN_TXT:%.txt=%.1}

%.1 %.5 %.7: %.xml
	$(XMLTO_SILENT) xmlto man $< 2>&1 | sed '/Note/d'

%.xml: %.txt ../../asciidoc.conf
	$(ASCIIDOC_SILENT) asciidoc --backend=docbook --doctype=manpage --conf-file ../../asciidoc.conf -a rs_version=$(PACKAGE_VERSION) -o $@ $<

CLEANFILES = $(man1_MANS)

dist_bin_SCRIPTS = coredump2packages \
                   retrace-server-bugzilla-query \
                   retrace-server-bugzilla-refresh \
                   retrace-server-cleanup \
                   retrace-server-interact\
                   retrace-server-plugin-checker\
                   retrace-server-reposync \
                   retrace-server-reposync-faf \
                   retrace-server-task \
                   retrace-server-worker

EXTRA_DIST = $(man1_MANS)
