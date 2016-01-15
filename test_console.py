import backup


folder = "/tmp/dump"

#-- TMVERSION: #1#
#-- DB: #mihanentalpo_me#
#-- TBL: #wp_commentmeta#
#-- TABLEUPDATEDATE: #2015-11-29 12:53:53#

bash_file = folder + "/old_dump_info.sh"

text = """
FOLDER="{folder}"
cd $FOLDER
IFS=$'\\n'
FILES=`find -name "*.sql"`
for FILE in $FILES
do
    echo "File: $FILE"
    tail -n5 "$FILE"


    exit
done
IFS=" "
echo "Done, FILES=$FILES"
""".format(folder=folder)

host = "mihanentalpo.me"
backup.Console.write_file(bash_file, text, host)

cmd = "ssh " + host + " bash " + bash_file

print(backup.Console.call_shell_and_return(cmd).decode("UTF-8"))

