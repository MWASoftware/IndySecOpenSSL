#!/bin/bash

#This script is used to update release numbers and freshen PDF versions
#of documentation. It applies to both Delphi and Lazarus packages.
#
#The most recent tag is assumed to be in <major>-<minor>-<release> format
#It is parsed and the user asked to confirm this as the current release
#or to override any or all values. The packages are then updated with the
#new release number, the result committed and a new tag set to this commit.
#copies revision information into the lpk files.

doupdate ()
{
	CHANGEDATE=`git log |grep '^Date:'|head -n 1|awk '{print $2 ", " $4, $3, $6, $5, $7};'`
	REVISION=`git rev-list --count HEAD`
	echo "Update in `pwd`"
	
	V1="0"
	V2="0"
	V3="0"

	VERSION=`git tag -l | tail -n 1`
	if [ -n "$VERSION" ]; then
	  echo "Most Recent Version is $VERSION"
	  echo -n "Continue?[Y/n]"
	  read LINE
	  if [ "$LINE" != "Y" ]; then exit; fi
   	  V1=`echo "$VERSION"|sed 's/\([0-9]\+\)\-\([0-9]\+\)-\([0-9]\+\)/\1/'`
	  V2=`echo "$VERSION"|sed 's/\([0-9]\+\)\-\([0-9]\+\)-\([0-9]\+\)/\2/'`
	  V3=`echo "$VERSION"|sed 's/\([0-9]\+\)\-\([0-9]\+\)-\([0-9]\+\)/\3/'`
	fi
	
	echo -n "Enter Major Number[$V1]:"
	read LINE
	if [ -n "$LINE" ]; then V1=$LINE; fi
	echo -n "Enter Minor Number[$V2]:"
	read LINE
	if [ -n "$LINE" ]; then V2=$LINE; fi
	echo -n "Enter Release Number[$V3]:"
	read LINE
	if [ -n "$LINE" ]; then V3=$LINE; fi
	
	echo -n "Updating to $V1.$V2.$V3.$REVISION dated $CHANGEDATE. Is this correct?[Y/n]"
	read LINE
    if [ "$LINE" != "Y" ]; then exit; fi

	NEWTAG="$V1-$V2-$V3"
	
	if [ -f src/IdSecOpenSSL.pas ]; then
	sed -i "s/IdSec_Major.*/IdSec_Major = $V1;/
		s/IdSec_Minor.*/IdSec_Minor = $V2;/
		s/IdSec_Release.*/IdSec_Release = $V3;/
		s/IdSec_Version.*/IdSec_Version = '$V1.$V2.$V3';/" src/IdSecOpenSSL.pas
	fi

	for PKG in `find . -name '*.lpk' -print`; do
		sed -i "/<CompilerOptions/,/<\/CompilerOptions/ ! { /<PublishOptions/,/<\/PublishOptions/ ! {s/<Version.*\/>/<Version Major=\"$V1\" Minor=\"$V2\" Release = \"$V3\" Build=\"$REVISION\" \/>/}}" $PKG
	done
	
	for DPRG in `find . -name '*.dproj' -print`; do
	  sed -i "s/\(MajorVer\">\)[0-9]\+</\1$V1</
	          s/\(MinorVer\">\)[0-9]\+</\1$V2</
	          s/\(Release\">\)[0-9]\+</\1$V3</	          
	          s/\(Build\">\)[0-9]\+</\1$REVISION</
	          s/\(FileVersion=\)[0-9\.]\+/\1$V1.$V2.$V3.$REVISION/
	          s/\(ProductVersion=\)[0-9\.]\+/\1$V1.$V2.$V3.$REVISION/"	 $DPRG          
	done
	
	find . -type f \( -name '*.odt' -o -name '*.ods' \) -print0 | while IFS= read -r -d '' DOC; do
	  PDF=`echo "$DOC" | sed 's/\(.*\)\.od[t|s]$/\1.pdf/'`
	  if [ ! -f "$PDF" ] || [ "$DOC" -nt "$PDF" ]; then
	    OUTDIR=`dirname "$DOC"`
	    libreoffice --invisible --convert-to pdf --outdir "$OUTDIR" "$DOC"
	    git add "$PDF" >/dev/null 2>&1
	  fi
	done
	git commit -a -m "Revision $NEWTAG commited" 
	git tag -f "$NEWTAG"
}
	
if [ -n "`ps ax|grep libreoffice|grep -v grep`" ]; then
  echo "libreoffice is running. Please terminate all instances of libreoffice before running this script"
  exit 1
fi

doupdate
exit 0

