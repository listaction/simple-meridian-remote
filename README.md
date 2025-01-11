# simple-meridian-remote remote control for meridian zone 218 controller

scans private subnets for anything listening on port 9014 
assumes its a meridian 218 zone controller 
provides volume control and mute

## why ?
the meridian audio app on app store performs very poorly and does not locate the zone controller most of the time 

# pre-req (python 3.10+) 
```
pip install -r requirements.txt
```

# running
```
python3 volume-control.py
```
