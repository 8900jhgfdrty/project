import turtle

def butterfly(site=4):
    size_wing = 1  

    turtle.seth(0)
    turtle.speed(5)
    turtle.pensize(1)
    turtle.speed(7)

    x, y = 0, 0
    y = y - 40 * size_wing
    turtle.pu()
    turtle.goto(x, y)
    turtle.pd()

    
    turtle.color('#FF8181')
    turtle.begin_fill()
    turtle.lt(90 + 30)
    turtle.fd(50 * size_wing)
    turtle.circle(50 * size_wing, 250)
    turtle.rt(80)
    turtle.circle(34 * size_wing, 196)
    turtle.end_fill()
    turtle.rt(95)
    turtle.fd(5 * size_wing)   

    
    turtle.begin_fill()
    turtle.lt(90)
    turtle.fd(50 * size_wing)
    turtle.circle(-50 * size_wing, 250)
    turtle.lt(80)
    turtle.circle(-34 * size_wing, 196)
    turtle.end_fill()

    
    turtle.pu()
    turtle.color('black')
    turtle.goto(x, y)
    turtle.seth(90 + 30)
    turtle.pensize(3)
    turtle.rt(90)  
    turtle.fd(2)
    turtle.lt(90)
    turtle.fd(50)
    turtle.pd()
    turtle.circle(100, 40)
    turtle.dot(12, 'black')
    turtle.pu()
    turtle.lt(180)
    turtle.circle(-100, 40)
    turtle.pd()
    turtle.lt(180)
    turtle.circle(-100, 40)
    turtle.dot(12, 'black')

    
    turtle.pu()
    turtle.color('black')
    turtle.goto(x, y)
    turtle.seth(90 + 30)
    turtle.fd(-10)
    turtle.rt(90)   
    turtle.fd(11)
    turtle.lt(90)
    turtle.rt(10)
    turtle.pd()
    turtle.begin_fill()
    turtle.circle(150, 30)
    turtle.circle(2, 140)
    turtle.circle(150, 30)
    turtle.circle(9, 160)
    turtle.end_fill()

   
    turtle.pu()
    turtle.color('black')
    turtle.goto(x, y)  
    turtle.seth(90 + 30)
    turtle.lt(45)
    turtle.fd(60)
    turtle.dot(15, 'black')
    turtle.rt(5)
    turtle.fd(30)
    turtle.dot(30, 'black')

    
    turtle.pu()
    turtle.color('black')
    turtle.goto(x, y)   
    turtle.seth(90 + 30)
    turtle.rt(45)
    turtle.fd(60)
    turtle.dot(15, 'black')
    turtle.rt(8)
    turtle.fd(35)
    turtle.dot(30, 'black')


    
    turtle.hideturtle()
    turtle.done()
    return None


if __name__ == '__main__':
    butterfly()
