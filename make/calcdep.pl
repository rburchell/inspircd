#!/usr/bin/env perl

#
# InspIRCd -- Internet Relay Chat Daemon
#
#   Copyright (C) 2009-2010 Daniel De Graaf <danieldg@inspircd.org>
#
# This file is part of InspIRCd.  InspIRCd is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


use strict;
use warnings;
use POSIX qw(getcwd);

sub find_output;
sub gendep($);
sub dep_cpp($$$);
sub dep_so($);
sub dep_dir($);
sub run();

my %f2dep;

run;
exit 0;

sub run() {
	my $build = $ENV{BUILDPATH};
	mkdir $build;
	chdir $build or die "Could not open build directory: $!";
	unlink 'include';
	symlink "$ENV{SOURCEPATH}/include", 'include';
	mkdir $_ for qw/bin modules obj/;
# BSD make has a horribly annoying bug resulting in an extra chdir of the make process
# Create symlinks to work around it
	symlink "../$_", "obj/$_" for qw/bin modules obj/;

	$build = getcwd();
	open MAKE, '>real.mk' or die "Could not write real.mk: $!";
	chdir "$ENV{SOURCEPATH}/src";

	if ($ENV{PURE_STATIC}) {
		run_static();
	} else {
		run_dynamic();
	}
	close MAKE;
}

sub run_dynamic() {
	my $build = $ENV{BUILDPATH};
	print MAKE <<END;
# DO NOT EDIT THIS FILE
# It is autogenerated by make/calcdep.pl, and will be overwritten
# every time you rerun make in the main directory
VPATH = \$(SOURCEPATH)/src

bad-target:
	\@echo "This Makefile must be run by a sub-make from the source"
	\@echo "in order to set the correct environment variables"
	\@exit 1

all: inspircd commands modules

END
	my(@core_deps, @cmdlist, @modlist);
	for my $file (<*.cpp>, <modes/*.cpp>, <socketengines/*.cpp>, "threadengines/threadengine_pthread.cpp") {
		my $out = find_output $file;
		dep_cpp $file, $out, 'gen-o';
		next if $file =~ m#^socketengines/# && $file ne "socketengines/$ENV{SOCKETENGINE}.cpp";
		push @core_deps, $out;
	}

	for my $file (<commands/*.cpp>) {
		my $out = dep_so $file;
		push @cmdlist, $out;
	}

	opendir my $moddir, 'modules';
	for my $file (sort readdir $moddir) {
		next if $file =~ /^\./;
		if (-e "modules/extra/$file" && !-l "modules/$file") {
			# Incorrect symlink?
			print "Replacing symlink for $file found in modules/extra\n";
			rename "modules/$file", "modules/$file~";
			symlink "extra/$file", "modules/$file";
		}
		if ($file =~ /^m_/ && -d "modules/$file" && dep_dir "modules/$file") {
			mkdir "$build/obj/$file";
			push @modlist, "modules/$file.so";
		}
		if ($file =~ /^m_.*\.cpp$/) {
			my $out = dep_so "modules/$file";
			push @modlist, $out;
		}
	}
	
	my $core_mk = join ' ', @core_deps;
	my $cmds = join ' ', @cmdlist;
	my $mods = join ' ', @modlist;
	print MAKE <<END;

bin/inspircd: $core_mk
	@\$(SOURCEPATH)/make/unit-cc.pl core-ld\$(VERBOSE) \$\@ \$^ \$>

inspircd: bin/inspircd

commands: $cmds

modules: $mods

.PHONY: all bad-target inspircd commands modules

END
}

sub run_static() {
	print MAKE <<END;
# DO NOT EDIT THIS FILE
# It is autogenerated by make/calcdep.pl, and will be overwritten
# every time you rerun make in the main directory
VPATH = \$(SOURCEPATH)/src

bad-target:
	\@echo "This Makefile must be run by a sub-make from the source"
	\@echo "in order to set the correct environment variables"
	\@exit 1

all: inspircd

END
	my(@deps, @srcs);
	for my $file (<*.cpp>, <modes/*.cpp>, <socketengines/*.cpp>, <commands/*.cpp>,
			<modules/*.cpp>, <modules/m_*/*.cpp>, "threadengines/threadengine_pthread.cpp") {
		my $out = find_output $file, 1;
		if ($out =~ m#obj/([^/]+)/[^/]+.o$#) {
			mkdir "$ENV{BUILDPATH}/obj/$1";
		}
		dep_cpp $file, $out, 'gen-o';
		next if $file =~ m#^socketengines/# && $file ne "socketengines/$ENV{SOCKETENGINE}.cpp";
		push @deps, $out;
		push @srcs, $file;
	}

	my $core_mk = join ' ', @deps;
	my $core_src = join ' ', @srcs;
	print MAKE <<END;

obj/ld-extra.cmd: $core_src
	\@\$(SOURCEPATH)/make/unit-cc.pl gen-ld\$(VERBOSE) \$\@ \$^ \$>

bin/inspircd: obj/ld-extra.cmd $core_mk
	\@\$(SOURCEPATH)/make/unit-cc.pl static-ld\$(VERBOSE) \$\@ \$^ \$>

inspircd: bin/inspircd

.PHONY: all bad-target inspircd

END
}

sub find_output {
	my($file, $static) = @_;
	my($path,$base) = $file =~ m#^((?:.*/)?)([^/]+)\.cpp# or die "Bad file $file";
	if ($path eq 'modules/' || $path eq 'commands/') {
		return $static ? "obj/$base.o" : "modules/$base.so";
	} elsif ($path eq '' || $path eq 'modes/' || $path =~ /^[a-z]+engines\/$/) {
		return "obj/$base.o";
	} elsif ($path =~ m#modules/(m_.*)/#) {
		return "obj/$1/$base.o";
	} else {
		die "Can't determine output for $file";
	}
}

sub gendep($) {
	my $f = shift;
	my $basedir = $f =~ m#(.*)/# ? $1 : '.';
	return $f2dep{$f} if exists $f2dep{$f};
	$f2dep{$f} = '';
	my %dep;
	my $link = readlink $f;
	if (defined $link) {
		$link = "$basedir/$link" unless $link =~ m#^/#;
		$dep{$link}++;
	}
	open my $in, '<', $f or die "Could not read $f";
	while (<$in>) {
		if (/^\s*#\s*include\s*"([^"]+)"/) {
			my $inc = $1;
			next if $inc eq 'inspircd_version.h' && $f eq '../include/inspircd.h';
			my $found = 0;
			for my $loc ("$basedir/$inc", "../include/$inc") {
				next unless -e $loc;
				$found++;
				$dep{$_}++ for split / /, gendep $loc;
				$loc =~ s#^\.\./##;
				$dep{$loc}++;
			}
			if ($found == 0 && $inc ne 'inspircd_win32wrapper.h') {
				print STDERR "WARNING: could not find header $inc for $f\n";
			} elsif ($found > 1 && $basedir ne '../include') {
				print STDERR "WARNING: ambiguous include $inc in $f\n";
			}
		}
	}
	close $in;
	$f2dep{$f} = join ' ', sort keys %dep;
	$f2dep{$f};
}

sub dep_cpp($$$) {
	my($file, $out, $type) = @_;
	gendep $file;

	print MAKE "$out: $file $f2dep{$file}\n";
	print MAKE "\t@\$(SOURCEPATH)/make/unit-cc.pl $type\$(VERBOSE) \$\@ \$(SOURCEPATH)/src/$file \$>\n";
}

sub dep_so($) {
	my($file) = @_;
	my $out = find_output $file;
	my $split = find_output $file, 1;

	if ($ENV{SPLIT_CC}) {
		dep_cpp $file, $split, 'gen-o';
		print MAKE "$out: $split\n";
		print MAKE "\t@\$(SOURCEPATH)/make/unit-cc.pl link-so\$(VERBOSE) \$\@ \$(SOURCEPATH)/src/$file \$>\n";
	} else {
		dep_cpp $file, $out, 'gen-so';
	}
	return $out;
}

sub dep_dir($) {
	my($dir) = @_;
	my @ofiles;
	opendir DIR, $dir;
	for my $file (sort readdir DIR) {
		next unless $file =~ /(.*)\.cpp$/;
		my $ofile = find_output "$dir/$file";
		dep_cpp "$dir/$file", $ofile, 'gen-o';
		push @ofiles, $ofile;
	}
	closedir DIR;
	if (@ofiles) {
		my $ofiles = join ' ', @ofiles;
		print MAKE "$dir.so: $ofiles\n";
		print MAKE "\t@\$(SOURCEPATH)/make/unit-cc.pl link-dir\$(VERBOSE) \$\@ \$^ \$>\n";
		return 1;
	} else {
		return 0;
	}
}

