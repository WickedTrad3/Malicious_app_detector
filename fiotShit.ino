boolean obstacleDetected = false;
int buttonState = 0;
int lastButtonState = 0;

void setup()
{
    Serial.begin(9600);
    pinMode(7, OUTPUT);       // LED pin
    pinMode(6, INPUT_PULLUP); // Push button pin
    pinMode(5, OUTPUT);       // Buzzer pin
    pinMode(4, OUTPUT);       // Motor pin
    pinMode(8, OUTPUT);       // Trig pin
    pinMode(9, INPUT);        // Echo pin
}

void loop()
{
    long duration, distance;
    digitalWrite(8, LOW); 
    delayMicroseconds(2);
    digitalWrite(8, HIGH);
    delayMicroseconds(5);
    digitalWrite(8, LOW);

    duration = pulseIn(9, HIGH);
    distance = duration / 58;

    if (distance > 0 && distance < 10)
    { 
        obstacleDetected = true;
        digitalWrite(4, HIGH); 
        digitalWrite(7, HIGH); 
        digitalWrite(5, HIGH);
    }
    else
    {
        obstacleDetected = false;
        digitalWrite(4, LOW); 
        digitalWrite(7, LOW); 
        digitalWrite(5, LOW); 
    }

    buttonState = digitalRead(6);
    if (buttonState != lastButtonState)
    {
        if (buttonState == LOW)
        {

            digitalWrite(7, HIGH);
            digitalWrite(5, HIGH);
            delay(1000);
            digitalWrite(7, LOW);
            digitalWrite(5, LOW);
        }
        lastButtonState = buttonState;
    }

    delay(100);
}

/*
Use eps01 for wifi
Add ThingSpeak data logging
Add Telegram integration
Develop mobile app for integration
Integrate with mobile app
*/