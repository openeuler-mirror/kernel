#!/bin/sh
# this scripts is used to patch functions for GCov in the following way
# This is style style_a
# //LCOV_EXCL_START
# void foo(void )
# {
#   .......
# }
# //LCOV_EXCL_STOP
# This is style_b
# //LCOV_EXCL_START
# void
# foo(void )
# {
#    ....
# }
# //LCOV_EXCL_STOP


FUNC_MAX_LINE=500
tags_file=./tags
func_records=./funcs
function_file=$1

function usage()
{
    echo "Usage: sh gcov_blacklist.sh function_list_file"
}

function func_style()
{
    func="$*"
    word=`echo "$func" | grep -P -o "\b.*\(" | sed "s/(//" | wc -w`
    if [[ "$word" > "1" ]]; then
        return 1
    else
        return 0
    fi
}

# check args
[ $# != 1 ] && usage && exit
[ ! -f $function_file ] && echo "error:$function_file does not exit" && exit
[ -f $func_records ] && rm $func_records

# create tags file
[ -f $tags_file ] && rm $tags_file
ctags -R * > /dev/null

# create func regx file
count=0
while read line;
do
    # line start with '#' and empty line are ignored
    echo $line | grep "#" > /dev/null && continue
    echo $line | grep -E "^\s?$" > /dev/null && continue
    func_name=`echo "$line" | awk '{print $1}'`
    grep -w $func_name $tags_file | sed -n "/;\"\tf/"p | awk -F"\t" '{print $2,$3}' | tee -a $func_records | tee > /dev/null && count=$(expr $count + 1)
done < $function_file

# add LCOV_EXCL
count=0
while read line;
do
    func=`echo "$line" | cut -d " " -f1 --complement | cut -d "/" -f2`
    func_style ${func}
    [ $? -eq "1" ] && style="style_a" || style="style_b"
    func=${func//\*/\\*}
    filename=`echo "$line" | awk '{print $1}'`
    # check filename
    echo $filename | grep -vE "\.c$|\.h$" > /dev/null && continue
    linenum=`sed -n "/${func}/,/{/=" $filename | head -n 1`
    if [[ "$style" == "style_a" ]]; then
        linenum=$(expr $linenum - 1)
    else
        linenum=$(expr $linenum - 2)
    fi
    sed -n ${linenum}p $filename | grep "LCOV_EXCL_START" > /dev/null || sed -i "${linenum}a\//LCOV_EXCL_START" $filename
    offset=$(grep "$func" -A $FUNC_MAX_LINE $filename | grep -n -m 1 "^}" | cut -d ":" -f 1)
    if [[ "$style" == "style_a" ]]; then
        linenum=`expr $linenum + $offset + 1`
    else
        linenum=`expr $linenum + $offset + 2`
    fi
    sed -n ${linenum}p $filename | grep "LCOV_EXCL_STOP" > /dev/null || sed -i "${linenum}a\//LCOV_EXCL_STOP" $filename
    [ $? == 0 ] && count=$(expr $count + 1)
done < $func_records

echo "done"
