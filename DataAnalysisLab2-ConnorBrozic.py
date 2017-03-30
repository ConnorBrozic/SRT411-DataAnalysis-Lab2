#SRT411 Data Analysis Lab 2
#By: Connor Brozic
#Code samples retrieved from Ch.3 of Data Driven Security Textbook

#Libraries to import and use
import urllib
import os.path
import pandas as pd
from IPython.display import HTML
import matplotlib.pyplot as plt
from matplotlib import cm
from numpy import arange

#Set paths to data
avURL = "http://datadrivensecurity.info/book/ch03/data/reputation.data"
avRep = "reputation.data"

#If data doesn't exist, download from website
if not os.path.isfile(avRep):
    urllib.urlretrieve(avURL, filename=avRep)

#Read data into a pandas dataframe
av = pd.read_csv(avRep,sep="#")

#Create column names for the data frame
av.columns = ["IP","Reliability","Risk","Type","Country","Locale","Coords","x"]

#Overview of the data frame
print(av)

#Overview of the first few rows of dataframe
av.head().to_csv(sys.stdout)

HTML(av.head(10),to_html())

#Summary of the Reliability Column
av['Reliability'].describe()

#Summary of the Risk Column
av['Risk'].describe()

#Define a function that acts similar to summary function in R
def factor_col(col):
 factor = pd.Categorical.from_array(col)
 return pd.value_counts(factor,sort=True).reindex(factor.levels)
 
#Get a count of the variables in various data frame columns
rel_ct = pd.value_counts(av['Reliability'])
risk_ct = pd.value_counts(av['Risk'])
type_ct = pd.value_counts(av['Type'])
country_ct = pd.value_counts(av['Country'])

#Generate table of values similar to R for Reliability and Risk Columns
print factor_col(av['Reliability'])
print factor_col(av['Risk'])

#Generate table of values for column 'Type', showing top 10
print factor_col(av['Type']).head(n=10)

#Generate table of values for Country column, showing top 10
print factor_col(av['Country']).head(n=10)

##Create new plots of Reliability, Risk and Country 
#First, sort the data by country
country_ct = pd.value_counts(av['Country'])

#Plot the data for country
plt.axes(frameon=0) #Reduce junk on chart
country_ct[:20].plot(kind='bar', rot=0, title="Summary By Country", figsize=(8,5)).grid(False)

#Plot the data for Reliability
plt.axes(frameon=0) # reduce chart junk
factor_col(av['Reliability']).plot(kind='bar', rot=0, title="Summary By 'Reliability'", figsize=(8,5)).grid(False)

#Plot the data for Risk
plt.axes(frameon=0) # reduce chart junk
factor_col(av['Risk']).plot(kind='bar', rot=0, title="Summary By 'Risk'", figsize=(8,5)).grid(False)
    
#Extract top 10 most prevalent countries from the country data
top10country = pd.value_counts(av['Country'])[0:9]
top10country.astype(float) / len(av['Country'])
    
    
#Get the percentages of top 10 countries
top10 = pd.value_counts(av['Country'])[0:9] 
#Convert to percentages by dividing by number of rows and display the results
top10.astype(float) / len(av['Country'])


#Create contingency table for risk/reliable factors
pd.crosstab(av['Risk'], av['Reliability'])
#Create a graphical view of the contingency table
xtab = pd.crosstab(av['Reliability'], av['Risk'])
plt.pcolor(xtab,cmap=cm.Greens)
plt.yticks(arange(0.5,len(xtab.index), 1),xtab.index)
plt.xticks(arange(0.5,len(xtab.columns), 1),xtab.columns)
plt.colorbar()
    
    
#Create a three way contingency table using type as the additional factor.
#Create a new column as a copy of the Type column
av['newtype'] = av['Type']

#Replace multi-Type entries with Multiple values
av[av['newtype'].str.contains(";")] = "Multiples"

#Setup new crosstab structures for the plot
typ = av['newtype']
rel = av['Reliability']
rsk = av['Risk']
xtab = pd.crosstab(typ, [ rel, rsk ],
#Change row and column names
 rownames=['typ'], colnames=['rel', 'rsk'])

#Plot the contingency graph of Risk/Reliability to Type
xtab.plot(kind='bar',legend=False,
title="Risk ~ Reliabilty | Type").grid(False) 

#Plot new Contingency plot, with Scanning Hosts data removed.
rrt_df = av[av['newtype'] != "Scanning Host"]
typ = rrt_df['newtype']
rel = rrt_df['Reliability']
rsk = rrt_df['Risk']
xtab = pd.crosstab(typ, [ rel, rsk ],
 rownames=['typ'], colnames=['rel', 'rsk'])
xtab.plot(kind='bar',legend=False,
title="Risk ~ Reliabilty | Type").grid(False)


#Final Risk/Reliability to Type plot

#Malware Distribution and Domain removed.
rrt_df = rrt_df[rrt_df['newtype'] != "Malware distribution" ]
rrt_df = rrt_df[rrt_df['newtype'] != "Malware Domain" ]
#New datasets created for the plot
typ = rrt_df['newtype']
rel = rrt_df['Reliability']
rsk = rrt_df['Risk']
#Create the final plot with specified title.
xtab = pd.crosstab(typ, [ rel, rsk ],
 rownames=['typ'], colnames=['rel', 'rsk'])
