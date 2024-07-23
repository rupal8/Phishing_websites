import streamlit as st
import pickle
import pandas as pd
from urllib.parse import urlparse
import whois
import requests
from URL_Feature_Extraction import getDomain, havingIP, haveAtSign, getLength, getDepth, redirection, httpDomain, tinyURL, prefixSuffix, web_traffic, domainAge, domainEnd, iframe, mouseOver, rightClick, forwarding, featureExtraction

# Load XGBoost model
@st.cache_data
def load_model():
    return pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))

model = load_model()

# Streamlit application layout
st.title('Phishing Website Prediction')
url_input = st.text_input("Enter the URL here:", "")

if st.button("Predict"):
    if url_input:
        features = featureExtraction(url_input, label=0)
        if features is not None:
            features_df = pd.DataFrame([features], columns=['Domain', 'Have_IP', 'Have_At', 'URL_Length', 
                                                            'URL_Depth', 'Redirection', 'https_Domain', 
                                                            'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
                                                            'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over', 
                                                            'Right_Click', 'Web_Forwards'])
            features_df = features_df.drop(columns=['Domain'])

            prediction = model.predict(features_df)
            if prediction == 0:
                st.success("The URL is safe.")
            else:
                st.error("The URL is likely a phishing site.")
        else:
            st.error("Failed to extract features from the URL.")
    else:
        st.error("Please enter a URL to predict.")
