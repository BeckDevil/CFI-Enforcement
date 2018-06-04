#mode as a first parameter, compiler as a second parameter
if[! -f "lame-3.99.5.tar.gz" ]; then
	echo "Downloading lame ..."
	wget -q http://downloads.sourceforge.net/project/lame/lame/3.99/lame-3.99.5.tar.gz ||
		(echo "Download failed ....";
		 exit 1;
		)
	tar xf lame-3.99.5.tar.gz
fi;

tar xf lame-3.99.5.tar.gz
mv lame-3.99.5 lame-$1-$2
(
	cd lame-$1-$2
	CC="$2" CFLAGS="-lm -O3"  ./configure --enable-shared=no &> configure.log
	make -j4)  &> make.log;
	exit $?;
)
