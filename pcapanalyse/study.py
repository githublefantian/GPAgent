'''
def makebold(fn):
    def wrapped():
        print("<b>")
        fn()
        print("</b>")
        #return "<b>" + fn() + "</b>"
    return wrapped

def makeitalic(fn):
    def wrapped():
        print("<i>")
        fn()
        print("</i>")
        #return "<i>" + fn() + '</i>'
    return wrapped

#@makebold
#@makeitalic
def hello():
    print("hello world")

hello = makebold(makeitalic(hello))

hello()

#print(hello())
#print(hello())

hello()

'''
'''
import time


def timeit(func):
    def wrapper():
        start = time.clock()
        func()
        end = time.clock()
        print("used:%d" %(end - start))

    return wrapper

#@timeit
def foo():
    print("in foo()")

foo = timeit(foo)
foo()
'''

def log(f):
    def wrapped(x, y):
        print(x)
        print(y)
        return
