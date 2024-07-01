from turtle import *
import time

# Screen setup
s = Screen()
s.screensize(700, 1000)
speed(5)

# Function to move turtle to a specific position without drawing
def my_goto(x, y):
    penup()
    goto(x, y)
    pendown()

# Function to move turtle to a specific position without drawing
def myPosition(x, y):
    penup()
    goto(x, y)
    pendown()

# Doraemon drawing functions
def eyes():
    fillcolor("#ffffff")
    begin_fill()
    tracer(False)
    a = 2.5
    for i in range(120):
        if 0 <= i < 30 or 60 <= i < 90:
            a -= 0.05
            lt(3)
            fd(a)
        else:
            a += 0.05
            lt(3)
            fd(a)
    tracer(True)
    end_fill()

def beard():
    my_goto(-32, 135)
    seth(165)
    fd(60)

    my_goto(-32, 125)
    seth(180)
    fd(60)

    my_goto(-32, 115)
    seth(193)
    fd(60)

    my_goto(37, 135)
    seth(15)
    fd(60)

    my_goto(37, 125)
    seth(0)
    fd(60)

    my_goto(37, 115)
    seth(-13)
    fd(60)

def mouth():
    my_goto(5, 148)
    seth(270)
    fd(100)
    seth(0)
    circle(120, 50)
    seth(230)
    circle(-120, 100)

def scarf():
    fillcolor('#e70010')
    begin_fill()
    seth(0)
    fd(200)
    circle(-5, 90)
    fd(10)
    circle(-5, 90)
    fd(207)
    circle(-5, 90)
    fd(10)
    circle(-5, 90)
    end_fill()

def nose():
    my_goto(-10, 158)
    seth(315)
    fillcolor('#e70010')
    begin_fill()
    circle(20)
    end_fill()

def black_eyes():
    seth(0)
    my_goto(-20, 195)
    fillcolor('#000000')
    begin_fill()
    circle(13)
    end_fill()

    pensize(6)
    my_goto(20, 205)
    seth(75)
    circle(-10, 150)
    pensize(3)

    my_goto(-17, 200)
    seth(0)
    fillcolor('#ffffff')
    begin_fill()
    circle(5)
    end_fill()
    my_goto(0, 0)

def face():
    fd(183)
    lt(45)
    fillcolor('#ffffff')
    begin_fill()
    circle(120, 100)
    seth(180)
    fd(121)
    pendown()
    seth(215)
    circle(120, 100)
    end_fill()
    my_goto(63.56, 218.24)
    seth(90)
    eyes()
    seth(180)
    penup()
    fd(60)
    pendown()
    seth(90)
    eyes()
    penup()
    seth(180)
    fd(64)

def head():
    penup()
    circle(150, 40)
    pendown()
    fillcolor('#00a0de')
    begin_fill()
    circle(150, 280)
    end_fill()

def Doraemon():
    head()
    scarf()
    face()
    nose()
    mouth()
    beard()

    my_goto(0, 0)
    seth(0)
    penup()
    circle(150, 50)
    pendown()
    seth(30)
    fd(40)
    seth(70)
    circle(-30, 270)

    fillcolor('#00a0de')
    begin_fill()

    seth(230)
    fd(80)
    seth(90)
    circle(1000, 1)
    seth(-89)
    circle(-1000, 10)

    seth(180)
    fd(70)
    seth(90)
    circle(30, 180)
    seth(180)
    fd(70)

    seth(100)
    circle(-1000, 9)

    seth(-86)
    circle(1000, 2)
    seth(230)
    fd(40)

    circle(-30, 230)
    seth(45)
    fd(81)
    seth(0)
    fd(203)
    circle(5, 90)
    fd(10)
    circle(5, 90)
    fd(7)
    seth(40)
    circle(150, 10)
    seth(30)
    fd(40)
    end_fill()

    seth(70)
    fillcolor('#ffffff')
    begin_fill()
    circle(-30)
    end_fill()

    my_goto(103.74, -182.59)
    seth(0)
    fillcolor('#ffffff')
    begin_fill()
    fd(15)
    circle(-15, 180)
    fd(90)
    circle(-15, 180)
    fd(10)
    end_fill()

    my_goto(-96.26, -182.59)
    seth(180)
    fillcolor('#ffffff')
    begin_fill()
    fd(15)
    circle(15, 180)
    fd(90)
    circle(15, 180)
    fd(10)
    end_fill()

    my_goto(-133.97, -91.81)
    seth(50)
    fillcolor('#ffffff')
    begin_fill()
    circle(30)
    end_fill()

    my_goto(-103.42, 15.09)
    seth(0)
    fd(38)
    seth(230)
    begin_fill()
    circle(90, 260)
    end_fill()

    my_goto(5, -40)
    seth(0)
    fd(70)
    seth(-90)
    circle(-70, 180)
    seth(0)
    fd(70)

    my_goto(-103.42, 15.09)
    fd(90)
    seth(70)
    fillcolor('#ffd200')
    begin_fill()
    circle(-20)
    end_fill()
    seth(170)
    fillcolor('#ffd200')
    begin_fill()
    circle(-2, 180)
    seth(10)
    circle(-100, 22)
    circle(-2, 180)
    seth(180 - 10)
    circle(100, 22)
    end_fill()
    goto(-13.42, 15.09)
    seth(250)
    circle(20, 110)
    seth(90)
    fd(15)
    dot(10)
    my_goto(0, -150)

    black_eyes()

def ankur():
    fillcolor('#ffec40')
    begin_fill()
    right(25)
    forward(20)
    right(45)
    forward(20)
    left(70)
    forward(90)
    left(95)
    forward(75)
    left(85)
    forward(175)
    left(85)
    forward(75)
    left(95)
    forward(90)
    left(85)
    forward(18)
    end_fill()

def leftLeg():
    myPosition(-39, -25)
    fillcolor("#ffd699")
    begin_fill()
    right(89)
    forward(25)
    right(90)
    forward(50)
    right(90)
    forward(20)
    right(85)
    forward(50)
    end_fill()

def leftSock():
    myPosition(-36, -78)
    fillcolor("#ffffff")
    begin_fill()
    right(90)
    circle(80, 13)
    right(110)
    forward(22)
    right(85)
    forward(19)
    right(90)
    forward(21)
    end_fill()

def leftShoe():
    myPosition(-69, -112)
    fillcolor("#b5ae60")
    begin_fill()
    right(90)
    left(5)
    forward(56)
    left(105)
    forward(13)
    left(75)
    forward(20)
    right(90)
    forward(15)
    circle(10, 15)
    left(80)
    forward(4)
    circle(10, 15)
    left(40)
    circle(20, 15)
    forward(10)
    right(45)
    forward(15)
    circle(25, 25)
    end_fill()

def rightLeg():
    myPosition(60, -28)
    fillcolor("#ffd699")
    begin_fill()
    left(128)
    forward(25)
    right(95)
    forward(55)
    right(90)
    forward(20)
    right(85)
    forward(55)
    end_fill()

def rightSock():
    myPosition(64, -79)
    fillcolor("#ffffff")
    begin_fill()
    right(90)
    circle(90, 14)
    right(110)
    forward(23)
    right(90)
    forward(15)
    right(80)
    forward(21)
    end_fill()

def rightShoe():
    myPosition(64, -108)
    fillcolor("#b5ae60")
    begin_fill()
    right(100)
    forward(56)
    left(160)
    forward(25)
    right(68)
    forward(17)
    left(90)
    circle(18, 15)
    forward(5)
    left(75)
    forward(11)
    right(85)
    forward(20)
    left(45)
    circle(10, 30)
    left(25)
    forward(5)
    end_fill()

def myShirt():
    myPosition(-75, 48)
    fillcolor("red")
    begin_fill()
    left(72)
    forward(185)
    left(87)
    forward(75)
    right(68)
    circle(20, 8)
    circle(300, 23)
    left(90)
    circle(35, 17)
    right(38)
    circle(35, 17)
    left(58)
    forward(75)
    right(12)
    forward(140)
    right(40)
    forward(93)
    left(120)
    circle(-20, 65)
    left(75)
    forward(10)
    left(23)
    forward(88)
    right(31)
    forward(87)
    right(180)
    forward(108)
    right(180)
    forward(104)
    circle(10, 70)
    end_fill()

def myHead():
    myPosition(-20, 295)
    left(20)
    pensize(2)
    fillcolor('#fcc6a0')
    begin_fill()
    right(90)
    forward(40)
    right(90)
    circle(50, 80)
    left(10)
    circle(50, 80)
    left(2)
    circle(200, 50)
    left(48)
    forward(60)
    circle(45, 60)
    right(5)
    circle(100, 85)
    end_fill()
    fillcolor('black')
    begin_fill()
    pensize(2)
    right(170)
    circle(-100, 165)
    right(78)
    forward(26)
    right(87)
    forward(55)
    circle(45, 60)
    right(5)
    circle(100, 85)
    end_fill()
    fillcolor('#fcc6a0')
    begin_fill()
    right(180)
    circle(-100, 105)
    right(37)
    forward(49)
    pensize(2)
    left(130)
    forward(30)
    circle(-10, 70)
    right(50)
    forward(36)
    right(80)
    forward(50)
    pencolor('#fcc6a0')
    right(90)
    forward(30)
    end_fill()

def rightHand():
    myPosition(197, 209)
    pencolor('black')
    fillcolor('#fcc6a0')
    begin_fill()
    right(45)
    forward(6)
    left(55)
    forward(20)
    circle(-5, 70)
    right(100)
    forward(18)
    left(105)
    forward(18)
    circle(-5, 70)
    right(100)
    forward(18)
    left(145)
    forward(15)
    circle(-5, 70)
    right(100)
    forward(18)
    left(150)
    forward(13)
    circle(-5, 70)
    right(100)
    forward(15)
    left(150)
    forward(10)
    circle(-5, 70)
    right(100)
    forward(12)
    circle(60, 10)
    left(45)
    forward(6)
    right(90)
    forward(10)
    end_fill()

def leftHand():
    myPosition(-94, 242)
    fillcolor('#fcc6a0')
    begin_fill()
    right(10)
    forward(6)
    left(90)
    penup()
    forward(12)
    pendown()
    left(90)
    forward(8)
    left(90)
    forward(12)
    end_fill()

def myBis():
    myPosition(-103, 291)
    right(90)
    fillcolor('#02d302')
    begin_fill()
    right(90)
    forward(55)
    left(80)
    forward(12)
    left(10)
    forward(17)
    left(10)
    forward(12)
    left(80)
    forward(55)
    left(80)
    forward(12)
    left(10)
    forward(17)
    left(10)
    forward(12)
    left(80)
    left(80)
    forward(12)
    left(10)
    forward(17)
    left(10)
    forward(12)
    end_fill()
    penup()
    right(100)
    forward(20)
    right(90)
    forward(14)
    pendown()
    pencolor('#9c5e4a')
    fillcolor('#9c5e4a')
    begin_fill()
    for i in range(5):
        forward(15)
        right(144)
    end_fill()
    penup()
    forward(27)
    left(90)
    forward(16)
    left(90)
    forward(7)
    pendown()
    fillcolor('#9c5e4a')
    begin_fill()
    for i in range(5):
        forward(10)
        right(144)
    end_fill()
    penup()
    forward(20)
    right(90)
    forward(5)
    pendown()
    fillcolor('#9c5e4a')
    begin_fill()
    for i in range(5):
        forward(10)
        right(144)
    end_fill()
    penup()
    right(180)
    forward(6)
    pendown()
    fillcolor('#9c5e4a')
    begin_fill()
    for i in range(5):
        forward(10)
        right(144)
    end_fill()

def leftHand2():
    myPosition(-112, 284)
    pencolor('black')
    fillcolor('#fcc6a0')
    begin_fill()
    right(180)
    forward(31)
    left(90)
    for i in range(2):
        circle(4, 90)
    for i in range(3):
        right(180)
        for i in range(2):
            circle(4, 90)
    end_fill()

def myMouth():
    myPosition(-25, 200)
    left(65)
    fillcolor('#77332e')
    begin_fill()
    for i in range(2):
        circle(25, 90)
        circle(25 // 2, 90)
    end_fill()

def myEyebrow(x, y):
    myPosition(x, y)
    pensize(18)
    right(150)
    forward(25)
    right(90)
    for i in range(1):
        right(45)
        dot(15)
    left(55)
    forward(25)
    for i in range(1):
        right(45)
        dot(15)

def myEyelid(x, y):
    myPosition(x, y)
    pensize(2)
    left(170)
    circle(-23, 180)

def myallEyes1(x, y):
    myPosition(x, y)
    right(90)
    fillcolor('#000000')
    begin_fill()
    circle(18)
    end_fill()
    left(90)
    penup()
    forward(19)
    right(90)
    forward(7)
    pendown()
    fillcolor('#ffffff')
    begin_fill()
    left(90)
    circle(9)
    end_fill()

def myallEyes2(x, y):
    myPosition(x, y)
    right(90)
    fillcolor('#000000')
    begin_fill()
    circle(18)
    end_fill()
    left(90)
    penup()
    forward(19)
    right(90)
    forward(8)
    pendown()
    fillcolor('#ffffff')
    begin_fill()
    left(90)
    circle(9)
    end_fill()

def myRobot():
    myPosition(155, -105)
    left(93)
    color('red')
    pensize(7)

    begin_fill()
    forward(50)
    left(90)
    forward(50)
    left(90)
    forward(50)
    left(90)
    forward(50)
    left(90)
    end_fill()

    color('white')
    penup()
    left(90)
    forward(30)
    right(90)
    forward(12)
    pendown()
    pensize(3)
    circle(5)
    penup()
    forward(25)
    pendown()
    circle(5)

    penup()
    right(90)
    forward(20)
    right(90)
    pendown()

    begin_fill()
    forward(23)
    right(90)
    forward(5)
    right(90)
    forward(23)
    right(90)
    forward(5)
    right(90)
    end_fill()

    penup()
    forward(10)
    right(90)
    forward(22)
    pendown()
    color('#7c7678')
    begin_fill()
    for i in range(4):
        forward(10)
        right(90)
    end_fill()

    penup()
    forward(15)
    left(90)
    forward(25)
    left(90)
    pendown()
    color('#7c7678')
    begin_fill()
    for i in range(4):
        forward(10)
        right(90)
    end_fill()
    penup()
    forward(25)
    right(90)
    forward(10)
    pendown()

# Drawing Doraemon
Doraemon()

# Pause to observe Doraemon before transitioning
time.sleep(10)
clear()

# Drawing second character (new)
ankur()
leftLeg()
leftSock()
leftShoe()
rightLeg()
rightSock()
rightShoe()
myShirt()
myHead()
rightHand()
leftHand()
myBis()
leftHand2()
myMouth()
myEyebrow(-58, 270)
myEyebrow(88, 270)
myEyelid(-38, 268)
myEyelid(108, 268)
myallEyes1(-37, 248)
myallEyes2(108, 248)
myRobot()

done()