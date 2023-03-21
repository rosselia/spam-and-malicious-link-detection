## requested libraries
import numpy as np
import pandas as pd
import string
from PyQt5.QtWidgets import *
from PyQt5.QtGui import QFont
from PyQt5 import QtGui
from sklearn.preprocessing import LabelBinarizer, LabelEncoder
from tensorflow import keras
import re
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
import requests
import json


def main():
  app = QApplication(([]))
  window = QWidget()
  window.setGeometry(100, 100, 500, 400)
  window.setWindowTitle("Spam App")

  label = QLabel(window)
  label.setText("Spam Application")
  label.setFont(QFont("Arial",20))
  label.move(170,80)
  
  layout = QVBoxLayout()
  label1 = QLabel("aşağıya maili girebilirsiniz:")
  label1.setFont(QFont("Arial",20))


  textbox = QTextEdit()
  textbox.move(200,100)
  button = QPushButton("Check")
  button.clicked.connect(lambda: onClick(textbox.toPlainText()))
  layout.addWidget(label1)
  layout.addWidget(textbox)
  layout.addWidget(button)
  window.setLayout(layout)

  window.show()
  app.exec_()

data = pd.read_excel("trspam.xlsx")
dataFrame = pd.DataFrame(data)

data.head()
data.drop(data.columns[[2]], axis=1, inplace=True)

data = data.rename(columns={'0.0': 'mail', '0.0.1': 'state'})

dataFrame = data

print("Dataset Size: ", dataFrame.size)

layers = keras.layers
models = keras.models

## null değerleri çıkartma
dataFrame = dataFrame.dropna(how='any',axis=0)

## ham ve spamı 0 ve 1 olarak değiştirme
dataFrame['state'] = dataFrame['state'].replace(['ham'],0)
dataFrame['state'] = dataFrame['state'].replace(['spam'],1)

## metinlerden modelin genellemesini engelleyebilecek noktalama işaretlerini çıkarma
dataFrame.mail = dataFrame.mail.str.translate(str.maketrans('', '', string.punctuation))

## metinleri lowerCase yapma
dataFrame.mail = dataFrame.mail.str.lower()

## verilerin parçalanması
max_words = 100
tokenize = keras.preprocessing.text.Tokenizer(num_words=max_words, char_level=False)
train_size = int(len(dataFrame) * 0.7)
print ("Train size: %d" % train_size)
print ("Test size: %d" % (len(data) - train_size))

## datanın train ve test'e ayrılması
def train_test_split(dataFrame, train_size):
    train = dataFrame[:train_size]
    test = dataFrame[train_size:]
    return train, test
  
train_y, test_y = train_test_split(dataFrame['state'], train_size)
train_x, test_x = train_test_split(dataFrame['mail'], train_size)


## verileri  sayısal matrislere dönüştürme
tokenize.fit_on_texts(train_x)
x_train = tokenize.texts_to_matrix(train_x)
x_test = tokenize.texts_to_matrix(test_x)

## veri setini kategorilemek için ikili sınıf matris’ine dönüştürülmesi
encoder = LabelEncoder()
encoder.fit(train_y)
y_train = encoder.transform(train_y)
y_test = encoder.transform(test_y)

num_classes = np.max(y_train) + 1
y_train = keras.utils.to_categorical(y_train, num_classes)
y_test = keras.utils.to_categorical(y_test, num_classes)


## modelin oluşturulması
batch_size = 32  ## ağa verilen alt örneklerin sayısıdır
epochs = 10       ## veri setinin model üzerinden geçme sayısı
drop_ratio = 0.5  

model = models.Sequential()
model.add(layers.Dense(512, input_shape=(max_words,)))
model.add(layers.Activation('relu'))
model.add(layers.Dropout(drop_ratio))
model.add(layers.Dense(100))
model.add(layers.Activation('relu'))
model.add(layers.Dense(num_classes))
model.add(layers.Activation('softmax')) 

model.compile(loss='categorical_crossentropy',
              optimizer='adam',
              metrics=['accuracy'])

history = model.fit(x_train, y_train,
                    batch_size=batch_size,
                    epochs=epochs,
                    verbose=0,
                    validation_split=0.1)


model.save("model.h5")
keras.backend.clear_session()

## tahminleme
predict = model.predict(x_train)
score = model.evaluate(x_test, y_test,batch_size=batch_size, verbose=1)

print('Test loss:', score[0])
print('Test accuracy:', score[1])

def predict(title):
  temp = tokenize.texts_to_matrix([title])       
  prediction = model.predict(np.array([temp[0]]))
  acc = prediction[0][np.argmax(prediction)]
  if np.argmax(prediction)==0:
     predicted_label = "not spam"
  else:
    predicted_label = "spam"
                 
  print("Data          : " + title)
  print("Tahmin basari : %" + str(acc))  
  print("Tahmin durum  : " + str(predicted_label))  
  print("")

  return predicted_label

def Find(string):
    regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
    url = re.findall(regex, string)
    return [x[0] for x in url]
 
def onClick(content):
  predict(content)
  arr = Find(content)
  Urls = arr

  window1 = QWidget()  
  window1.setGeometry(100, 100, 500, 400)
  layout = QVBoxLayout()
  label1 = QLabel("Information Box")
  label1.setFont(QtGui.QFont("Sanserif", 20))
  label1.setStyleSheet('color:red')
  layout.addWidget(label1)

  if predict(content)=="spam":
    label3 = QLabel("Mail spam durumu: \n\nbu mail spam")
  else:
    label3 = QLabel("Mail spam durumu: \n\nbu mail spam değil")

  if not arr:
    label2 = QLabel("Link içerme durumu: \n\nbu mail link içermiyor")
  else:
    label2 = QLabel("Link içerme durumu: \n\nbu mail %s"% len(arr) +" adet link içeriyor")


  API_key = 'd55b7ba9114986486dab2ca615545e855be5f48f7ec2dced40b679946e94e6aa'
  url = 'https://www.virustotal.com/vtapi/v2/url/report'
  message2 = QMessageBox()

  parameters = {'apikey': API_key, 'resource': Urls}
  attention = 0
  if not Urls:
     label4 = QLabel(" ")
  for i in Urls:
      parameters = {'apikey': API_key, 'resource': i}

      response= requests.get(url=url, params=parameters)
      json_response= json.loads(response.text)
    
      if json_response['response_code'] <= 0:
          label4 = QLabel("Link güvenlik durumu: \n\n"+i +(" --> Bu bağlantı bulunamadı lütfen manuel olarak tarayın\n"))

      elif json_response['response_code'] >= 1:
          if json_response['positives'] <= 0:
            
            label4 = QLabel("Link güvenlik durumu: \n\n"+i + (" --> Hiçbir güvenlik satıcısı bu URL'yi kötü amaçlı olarak işaretlemedi \n"))

          else:
            
            label4 = QLabel("Link güvenlik durumu: \n\n"+i+" -->  " +str(json_response['positives'])+(" güvenlik sağlayıcısı bu URL'yi kötü amaçlı olarak işaretledi"))
            attention+=1

  
  label4.setStyleSheet('color:red')
  layout.addWidget(label2)
  layout.addWidget(label3)
  layout.addWidget(label4)
  window1.setLayout(layout)
  window1.show()
  message2.exec_()


if __name__ == '__main__':
   main()


# print("\n-Tahmin Edilmesi Beklenen Veriler-")  
# print("----------------------------------")
# predict("Sayın yetkili, Bizler 4275 kodlu GAZETECİLİK (LİSANS) bölümü mezunları olarak, gerek siyaset, sosyoloji, iktisat, hukuk ve iletişim olarak özetlenebilecek gördüğümüz dersler bakımından, gerekse fakültemizin bizlere kattığı ve günümüz dünyasında çok önemli yere sahip olan iletişim yeteneğine sahip bireyler olmamız bakımından kurumunuza fayda sunacağımızı belirtmek istiyoruz. Fazla zamanınızı almadan, kurumunuz memur alımlarındaki nitelik kodlarına 4275 kodunu eklemenizi rica eder iyi çalışmalar dileriz.")

# predict("Bu problem daha önce yoktu, dün rastladım.29 Mart 2012 19:54 tarihinde Cüneyt Özdemir , yazdı:> sen yanlış anladın sanırım. ben yılmaz hocanın sayfasında sıkıntı var> demedim. bu sitenin tamamının kodları ona ait onu söyledim. zaten tek> sayfa. sadece veri tabanından çekiyor bilgileri. bizdede kaspersky ")

## Merhaba! Birkaç gündür sizinle iletişim kurmaya çalışıyorduk. Geçen hafta sonu çekilişi, 1000 TL GARANTİLİ ödül kazandığınızı gösteriyor. 09064012160'ı arayın ya da www.google.com linkine tıklayın. Talep Kodu K52. Yalnızca 12 saat geçerlidir. Acele etmeyi unutmsyın. Müşteri temsilciniz Önder Akça