import axios from "axios";

const BASE_URL = "https://phisher-back.onrender.com/api";

export const getPrediction = async (url) => {
  try {
    console.log("Requesting for Prediction data ...");
    const res = await axios.post(`${BASE_URL}/predict/`, {
      url,
    });
    const data = res.data;
    return data;
  } catch (err) {
    console.log(err);
    return "Error while retreiving Prediction data : ", err.message;
  }
};
