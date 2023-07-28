# https://stackoverflow.com/questions/7039114/waiting-animation-in-command-prompt-python

import time


animation = "|/-\\"
idx = 0
while thing_not_complete():
    print(animation[idx % len(animation)], end="\r") # https://www.geeksforgeeks.org/gfact-50-python-end-parameter-in-print/
    idx += 1
    time.sleep(0.1)


bar = [
    " [=     ]",
    " [ =    ]",
    " [  =   ]",
    " [   =  ]",
    " [    = ]",
    " [     =]",
    " [    = ]",
    " [   =  ]",
    " [  =   ]",
    " [ =    ]",
]
i = 0

while True:
    print(bar[i % len(bar)], end="\r")
    time.sleep(.2)
    i += 1
