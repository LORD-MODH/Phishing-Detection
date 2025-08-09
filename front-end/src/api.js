import axios from 'axios'

const BASE_URL = "http://127.0.0.1:8000/api"




export const getPrediction = async (url) => {
  try{
    console.log('Requesting for Prediction data ...')
    const res = await axios.post(`${BASE_URL}/predict/`,{
      url
    });
    const data = res.data;
    return data;
  }catch(err){
    console.log(err);
    return ("Error while retreiving Prediction data : ",err.message);
  }

}