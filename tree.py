import random
from turtle import Screen, Turtle

def tree(branchLen, t):
    if branchLen > 3:
        if 8 <= branchLen <= 12:
            t.color('snow' if random.randint(0, 2) == 0 else 'lightcoral')
            t.pensize(branchLen / 3)
        elif branchLen < 8:
            t.color('snow' if random.randint(0, 1) == 0 else 'lightcoral')
            t.pensize(branchLen / 2)
        else:
            t.color('sienna')
            t.pensize(branchLen / 10)

        
        t.forward(branchLen)
        a = 1.5 * random.random()
        t.right(20 * a)
        b = 1.5 * random.random()
        tree(branchLen - 10 * b, t)
        t.left(40 * a)
        tree(branchLen - 10 * b, t)
        t.right(20 * a)
        t.backward(branchLen)

def petal(m, t):
    for i in range(m):
        a = 200 - 400 * random.random()
        b = 10 - 20 * random.random()
        t.up()
        t.forward(b)
        t.left(90)
        t.forward(a)
        t.down()
        t.color("lightcoral")
        t.circle(1)
        t.up()
        t.backward(a)
        t.right(90)
        t.backward(b)

def main():
    screen = Screen()
    screen.bgcolor('wheat') 
    t = Turtle()
    t.speed('fastest')  # Speed up drawing
    t.left(90)
    t.up()
    t.backward(150)
    t.down()
    t.color('sienna')
    tree(60, t)
    petal(100, t)
    screen.exitonclick()

main()
