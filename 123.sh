sed -n 's/.*Unknown symbol //p'  | awk '{print $1}' >./symbol
