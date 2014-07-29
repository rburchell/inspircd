/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2014 Robin Burchell <robin+git@viroteck.net>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* $CompileFlags: pkgconfversion("fuse","2.7.3") pkgconfincludes("fuse","/fuse_lowlevel.h","") -Wno-pedantic */
/* $LinkerFlags: pkgconflibs("fuse","/libfuse.so","-lfuse") */

#include <iostream>
#include <list>
#include <map>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include <list>

#define FUSE_USE_VERSION 26
#include <fuse_lowlevel.h>

class inode
{
public:
    inode();
    fuse_ino_t ino() const { return m_ino; }
    int nlink() const { return m_nlink; }
    int size() const { return m_size; }
    bool isDir() const { return m_isDir; }
    const char *name() const { return m_name; }
    void setName(const char *name) { m_name = name; }
    void setParent(inode *parent);
    fuse_ino_t parent() const { return m_parent; }
    const std::list<fuse_ino_t> &children() const { return m_children; }
    const char *content() const { return m_content; }
    void setContent(const char *content) { m_content = content; m_size = strlen(m_content); }

private:
    fuse_ino_t m_ino;
    fuse_ino_t m_parent;
    int m_nlink;
    int m_size; // TODO: update count for directories too? (number of dentries)
    bool m_isDir : 1;
    const char *m_name;

    // TODO: can we union this?
    // TODO: use a simple linked list instead of std::list?
    std::list<fuse_ino_t> m_children;
    const char *m_content;
};


static fuse_ino_t inoCount = FUSE_ROOT_ID;

inode::inode()
    : m_ino(inoCount++)
    , m_parent(0)
    , m_nlink(1) // dot-parent
    , m_size(0)
    , m_isDir(false)
    , m_name(0)
    , m_content(0)
{
}

void inode::setParent(inode *parent)
{
    // TODO: decrement nlink on old parent
    // TODO: assert that a parent has no contents?
    m_parent = parent->ino();
    parent->m_isDir = true;
    parent->m_nlink++;
    parent->m_children.push_back(ino());
}




extern std::map<fuse_ino_t, inode> nodes;


static int hello_stat(fuse_ino_t ino, struct stat *stbuf)
{
    stbuf->st_ino = ino;

    std::map<fuse_ino_t, inode>::const_iterator it = nodes.find(ino);
    if (it == nodes.end())
        return -1;

    inode i = it->second;
    if (i.isDir())
        stbuf->st_mode = S_IFDIR | 0755;
    else
        stbuf->st_mode = S_IFREG | 0444;

    stbuf->st_nlink = i.nlink();
    stbuf->st_size = i.size();
    return 0;
}

static void hello_ll_getattr(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	struct stat stbuf;

	(void) fi;

	memset(&stbuf, 0, sizeof(stbuf));
	if (hello_stat(ino, &stbuf) == -1)
		fuse_reply_err(req, ENOENT);
	else
		fuse_reply_attr(req, &stbuf, 1.0);
}

static void hello_ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    std::map<fuse_ino_t, inode>::const_iterator it = nodes.find(parent);

    if (it == nodes.end()) {
        // huh?
        fuse_reply_err(req, ENOENT);
        return;
    }

    inode pi = it->second;
    if (!pi.isDir()) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    for (auto cit = pi.children().begin(); cit != pi.children().end(); ++cit) {
        auto cnode = nodes.find(*cit);
        assert(cnode != nodes.end());
        inode child = cnode->second;

        if (strcmp(name, child.name()) == 0) {
            struct fuse_entry_param e;
            memset(&e, 0, sizeof(e));
            e.ino = child.ino();
            e.attr_timeout = 1.0;
            e.entry_timeout = 1.0;
            hello_stat(e.ino, &e.attr);

            fuse_reply_entry(req, &e);
            return;
        }
    }

    // not found
    fuse_reply_err(req, ENOENT);
}

struct dirbuf {
	char *p;
	size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name,
		       fuse_ino_t ino)
{
	struct stat stbuf;
	size_t oldsize = b->size;
	b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
	b->p = (char *) realloc(b->p, b->size);
	memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_ino = ino;
	fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf,
			  b->size);
}

#define min(x, y) ((x) < (y) ? (x) : (y))

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
			     off_t off, size_t maxsize)
{
	if (off < bufsize)
		return fuse_reply_buf(req, buf + off,
				      min(bufsize - off, maxsize));
	else
		return fuse_reply_buf(req, NULL, 0);
}

static void hello_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			     off_t off, struct fuse_file_info *fi)
{
	(void) fi;


    std::map<fuse_ino_t, inode>::const_iterator it = nodes.find(ino);

    if (it == nodes.end()) {
        // TODO: right code?
        fuse_reply_err(req, ENOENT);
        return;
    }

    inode pi = it->second;
    if (!pi.isDir()) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }

    struct dirbuf b;
    memset(&b, 0, sizeof(b));
    dirbuf_add(req, &b, ".", pi.ino());
    dirbuf_add(req, &b, "..", pi.parent() ? pi.parent() : pi.ino()); // special casing is for the root inode

    for (auto cit = pi.children().begin(); cit != pi.children().end(); ++cit) {
        std::map<fuse_ino_t, inode>::const_iterator cnode = nodes.find(*cit);
        assert(cnode != nodes.end());
        inode child = cnode->second;

        dirbuf_add(req, &b, child.name(), child.ino());
    }

    reply_buf_limited(req, b.p, b.size, off, size);
    free(b.p);
}

static void hello_ll_open(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
    std::map<fuse_ino_t, inode>::const_iterator it = nodes.find(ino);

    if (it == nodes.end()) {
        // TODO: right error?
        fuse_reply_err(req, ENOENT);
        return;
    }

    inode pi = it->second;
    if (pi.isDir()) {
        // TODO: right error?
        fuse_reply_err(req, EISDIR);
        return;
    }

    if ((fi->flags & 3) != O_RDONLY)
        fuse_reply_err(req, EACCES);
    else
        fuse_reply_open(req, fi);
}

static void hello_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t off, struct fuse_file_info *fi)
{
    (void) fi;

    std::map<fuse_ino_t, inode>::const_iterator it = nodes.find(ino);

    if (it == nodes.end()) {
        // TODO: right error?
        fuse_reply_err(req, ENOENT);
        return;
    }

    inode pi = it->second;
    if (pi.isDir()) {
        // TODO: right error?
        fuse_reply_err(req, ENOENT);
        return;
    }

    reply_buf_limited(req, pi.content(), pi.size(), off, size);
}

static struct fuse_lowlevel_ops hello_ll_oper = {
	.lookup		= hello_ll_lookup,
	.getattr	= hello_ll_getattr,
	.readdir	= hello_ll_readdir,
	.open		= hello_ll_open,
	.read		= hello_ll_read,
};


/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2007 Dennis Friis <peavey@inspircd.org>
 *   Copyright (C) 2007 Robin Burchell <robin+git@viroteck.net>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"

std::map<fuse_ino_t, inode> nodes;

class FuseSocket : public EventHandler
{
public:
    FuseSocket(fuse_session *se, fuse_chan *ch);
    void HandleEvent(EventType et, int errornum = 0);

private:
    fuse_chan *m_channel;
    fuse_session *m_session;
};

FuseSocket::FuseSocket(fuse_session *se, fuse_chan *ch)
    : EventHandler()
    , m_channel(ch)
    , m_session(se)
{
    std::cout << "Got FD " << fuse_chan_fd(ch) << std::endl;
    SetFd(fuse_chan_fd(ch));
}

void FuseSocket::HandleEvent(EventType et, int errornum)
{
//    std::cout << "HandleEvent" << std::endl;
    if (et == EVENT_READ) {
        size_t size = fuse_chan_bufsize(m_channel);
        char *buf = (char *) malloc(size);

        if (fuse_session_exited(m_session)) {
            // TODO: exit
            std::cout << "HandleEvent: fuse_session_exited!";
        }

        int res = fuse_chan_recv(&m_channel, buf, size);
        if (res > 0) {
            fuse_session_process(m_session, buf, res, m_channel);
        } else if (fuse_session_exited(m_session) != 0) {
            // TODO: exit
            std::cout << "HandleEvent: fuse_session_exited 2!";
        }
    } else {
        if (et == EVENT_WRITE)
            std::cout << "I can't handle EVENT_WRITE!" << std::endl;
        else if (et == EVENT_ERROR)
            std::cout << "Got EVENT_ERROR" << std::endl;
        else
            std::cout << "I have literally no idea" << std::endl;
        throw ModuleException("Unknown event type");
    }
}

class ModuleIRCFS : public Module
{
public:
    ModuleIRCFS()
    {
        {
            inode n;

            inode c;
            c.setName("hello");
            c.setParent(&n);
            c.setContent("Hello world!\n");

            inode c2;
            c2.setName("world");
            c2.setParent(&n);
            c2.setContent("The second file ever created.\n");

            inode subdir;
            subdir.setName("asubdir");
            subdir.setParent(&n);

            inode insubdir;
            insubdir.setName("moreData");
            insubdir.setParent(&subdir);
            insubdir.setContent("some more random and useless crap");

            nodes[n.ino()] = n;
            nodes[c.ino()] = c;
            nodes[c2.ino()] = c2;
            nodes[subdir.ino()] = subdir;
            nodes[insubdir.ino()] = insubdir;
        }

        char *fargv[] = { "fake_argv", "ircfs", NULL };
        int fargc = 2;
        struct fuse_args args = FUSE_ARGS_INIT(fargc, fargv); // TODO: fuse_opt_free_args?

        if (fuse_parse_cmdline(&args, &m_mountpoint, NULL, NULL) == -1)
            throw ModuleException("Couldn't parse cmdline?");

        m_ch = fuse_mount(m_mountpoint, &args);
        if (!m_ch)
            throw ModuleException("Couldn't mount!");


        std::cout << "Creating session" << std::endl;
        m_se = fuse_lowlevel_new(&args, &hello_ll_oper,
                       sizeof(hello_ll_oper), NULL);
        FuseSocket *s = new FuseSocket(m_se, m_ch);
        std::cout << "Created FuseSocket" << std::endl;
        ServerInstance->SE->AddFd(s, FD_WANT_POLL_READ | FD_WANT_NO_WRITE);
        fuse_session_add_chan(m_se, m_ch);
    }

    ~ModuleIRCFS()
    {
        fuse_session_remove_chan(m_ch);
        fuse_session_destroy(m_se);
        fuse_unmount(m_mountpoint, m_ch);
//        fuse_opt_free_args(&args);
        free(m_mountpoint);
    }

    Version GetVersion()
    {
        return Version("Provides a filesystem interface for the data in the IRC daemon.", VF_VENDOR);
    }
private:
    char *m_mountpoint;
    fuse_session *m_se;
    fuse_chan *m_ch;
};

MODULE_INIT(ModuleIRCFS)

