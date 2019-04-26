# -*- coding: utf-8 -*-

from django.shortcuts import render
from django.views.decorators import csrf
from os import system
from time import time, localtime, strftime

logfile = ''
ctx = {
    'attack':'-',
    'ss':'x',
    'got':'x',
    'crb':'x',
    'port':0,
}
def index(request):
    global logfile
    global ctx
    atbl = {
        'ret2libc':1001,
        'rop1':1002,
        'rop2':1003,
        'jop':1004,
    }
    dtbl = {
        'ss':100,
        'got':200,
        'crb':300,
    }
    if request.POST:
        attack = request.POST.get('attack',None)
        defend = request.POST.getlist('defend',None)
        port = atbl[attack]
		defend_flag = ['_','_','_']
        for i in defend:
            port += dtbl[i]
            ctx[i] = '√'
			defend_flag[dtbl.key().index(i)] = i[0]
		defend_file = ''
		for i in defend_flag:
			defend_file += i
        ctx['attack'] = attack
        ctx['port'] = str(port)
        now = int(time())
        stamp = strftime('%Y%m%d_%H%M%S',localtime(now))
        logfile = './log/log_'+attack+'('+defend_file+')'+str(port)+'_'+stamp
        ctx['log'] = logfile
        cmd = './start_with_pin ' + str(port) +' ./'+ attack + ' '+ logfile + ' ' + defend_file + '.so &'
		system(cmd)
    return render(request, "post.html", ctx)

def result(request):
    global ctx
    if request.POST:
        text = open(logfile,'r').read()
        ctx['text'] = text
    return render(request, "post.html", ctx)
