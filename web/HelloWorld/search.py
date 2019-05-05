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
        'demo1':1101,
        'demo2':1102,
        'demo3':1103,
    }
    dtbl = {
        'ss':100,
        'got':50,
        'crb':200,
        'thr':400,
    }
    if request.POST:
        attack = request.POST.get('attack',None)
        defend = request.POST.getlist('defend',None)
        port = atbl[attack]
        defend_flag = ['_','_','_','_']
        for i in defend:
            port += dtbl[i]
            ctx[i] = '√'
            defend_flag[list(dtbl.keys()).index(i)] = i[0]
        defend_file = ''
        for i in defend_flag:
            defend_file += i
        ctx['attack'] = attack
        ctx['port'] = str(port)
        now = int(time())
        stamp = strftime('%Y%m%d_%H%M%S',localtime(now))
        logfile = './log/log_'+attack+'_'+defend_file+'_'+str(port)+'_'+stamp
        ctx['log'] = logfile
        cmd = './start_with_pin ' + str(port) +' ./'+ attack + ' '+ logfile + ' ' + defend_file + '.so &'
        system(cmd)
        ctx['text'] = ''
    return render(request, "post.html", ctx)

def result(request):
    global ctx
    if request.POST:
        text = open(logfile,'r').read()
        ctx['text'] = text
    return render(request, "post.html", ctx)
