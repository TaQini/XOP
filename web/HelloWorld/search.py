# -*- coding: utf-8 -*-

from django.shortcuts import render
from django.views.decorators import csrf
from os import system
from time import time, localtime, strftime
from netifaces import ifaddresses

logfile = ''
host = ifaddresses('wlp1s0')[2][0]['addr']

def index(request):
    global logfile
    global ctx
    ctx = {
        'attack':'-',
        'ss':'x',
        'got':'x',
        'crb':'x',
        'thr':'x',
        'host':host,
        'port':0,
    }
    atbl = {
        'demo1':1100,
        'demo2':2100,
        'demo3':3100,
    }
    dtbl = {
        'ss':1,
        'got':2,
        'crb':4,
        'thr':8,
    }
    if request.POST:
        attack = request.POST.get('attack',None)
        defend = request.POST.getlist('defend',None)
        defend_flag = ['_','_','_','_']
        port = atbl[attack]
        for i in defend:
            port += dtbl[i]
            ctx[i] = '√'
            defend_flag[list(dtbl.keys()).index(i)] = i[0]
        defend_file = ''

        # defend selector for MyPinTool
        flag = str(port - atbl[attack])
        tmp = open('/tmp/flag','w+')
        tmp.write(flag)
        tmp.close()

        for i in defend_flag:
            defend_file += i

        ctx['attack'] = attack
        ctx['port'] = str(port)
        now = int(time())
        stamp = strftime('%Y%m%d_%H%M%S',localtime(now))
        logfile = './log/log_'+attack+'_'+defend_file+'_'+str(port)+'_'+stamp
        ctx['log'] = logfile
        cmd = './start_with_pin ' + str(port) +' ./'+ attack + ' '+ logfile + ' &'
        system(cmd)
        ctx['text'] = ''
    return render(request, "post.html", ctx)

def result(request):
    global ctx
    if request.POST:
        text = open(logfile,'r').read()
        ctx['text'] = text
    return render(request, "post.html", ctx)
