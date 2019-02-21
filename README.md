# RaRedirector
EosSdk based agent to source-based routing using PBR for certain prefixes.


Steps:

1. Copy the RaRedirector.py file to /mnt/flash/ on the Arista switch
2. Create the Mount Profile:  
```
bin=/mnt/flash/RaRedirector
[ ${bin%.*} == $bin ] || echo "Error: remove dots from binary name"
name=$(basename $bin)
dest=/usr/lib/SysdbMountProfiles/$name
source="/usr/lib/SysdbMountProfiles/EosSdkAll"
cat $source | sed "1s/agentName[ ]*:.*/agentName:${name}-%sliceId/" > /tmp/tmp_$name
delta=$(cmp /tmp/tmp_$name $source)
if [ "$?" = "0" ]; then
  echo "Error: something is wrong"
else
  sudo mv /tmp/tmp_$name $dest
fi
```

3. In CLI, start the daemon:
```
daemon RaRedirector
   exec /mnt/flash/RaRedirector
   no shutdown
```
