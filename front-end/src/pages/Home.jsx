import { useEffect, useMemo, useState, useRef } from 'react';
// TextPlugin is no longer needed for this approach
import Search from '../components/Search';
import { getPrediction } from '../api';
import { gsap } from "gsap";
import { useGSAP } from "@gsap/react";
import { SplitText } from "gsap/SplitText";

gsap.registerPlugin(useGSAP);
gsap.registerPlugin(SplitText);

const Home = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [loading,setLoading] = useState(false);
  const [error,setError] = useState(false);
  const [predictionDetail,setPredictionDetail] = useState({
    prediction:null,
    info:[],
    url:null
  })
  const typedTextRef = useRef(null);
  const cursorRef = useRef(null);

  useGSAP(()=>{
    const split = new SplitText("#para", { type: "lines" });
    gsap.from(split.lines, {
      duration: 1,
      yPercent: 100,
      opacity: 0,
      ease: "power3.out",
      stagger: 0.3,
    });
  },[predictionDetail])

  const textsToType = useMemo(() => [
    "One Click Away From a Breach? Not Anymore",
    "Protect Your Reputation. Secure Every Inbox",
    "We Hunt the Phish, So You Don't Have To",
    "Real-Time Link & Attachment Analysis"
  ], []);

  useEffect(() => {
    const masterTimeline = gsap.timeline({ repeat: -1 });

    textsToType.forEach(text => {
      // A proxy object to animate its 'index' property
      let proxy = { index: 0 };
      const textLength = text.length;

      const sentenceTimeline = gsap.timeline();

      // --- Typing Animation ---
      sentenceTimeline.to(proxy, {
        index: textLength,
        duration: textLength * 0.05, // Typing speed
        ease: 'none',
        onStart: () => {
          // Show cursor when typing starts
          gsap.set(cursorRef.current, { opacity: 1 });
        },
        onUpdate: () => {
          // On each update, set the text content to the substring
          typedTextRef.current.textContent = text.substring(0, Math.round(proxy.index));
        }
      })
      // --- Pause After Typing ---
      .to(cursorRef.current, {
        opacity: 1,
        duration: 1.5 // Pause duration
      })
      // --- Deleting Animation (Backspace) ---
      .to(proxy, {
        index: 0, // Animate index from textLength back to 0
        duration: textLength * 0.03, // Deleting speed
        ease: 'none',
        onUpdate: () => {
          // Same update logic creates the backspace effect
          typedTextRef.current.textContent = text.substring(0, Math.round(proxy.index));
        }
      })
       // --- Pause After Deleting ---
      .to(cursorRef.current, {
        opacity: 0,
        duration: 0.5 // Short pause before next sentence
      });

      masterTimeline.add(sentenceTimeline);
    });

    return () => {
      masterTimeline.kill();
    };
  }, [textsToType]);

  const handlePrediction = async (searchUrl) => {
    if(searchUrl!=''){
      try{
        setLoading(true);
        const {prediction,info,url} = await getPrediction(searchUrl);
        setPredictionDetail({prediction,info,url});
      }
      catch(err){
        console.log(err);
        setError(true);
      }
      finally{
        setLoading(false);
      }
    }
  }

  

  
  return (
    <main className='w-screen h-screen flex flex-col bg-primary '>
      <header className='p-4 pl-10 pt-7 flex justify-center sm:justify-start text-light-200 font-dm-sans'>
        <span className='text-2xl font-dm-sans'>PHISHER MAN</span>
      </header>
      <div className='p-4 m-4 mt-20 inline-flex justify-center items-center text-3xl md:text-5xl font-dm-sans font-bold h-20'>
        <span className='text-gradient' ref={typedTextRef}></span>
        {/* <span className="text-white animate-blink" ref={cursorRef} style={{ opacity: 0 }}>&#9474;</span> */}
      </div>
      <div className='p-20 flex flex-col justify-end items-center font-dm-sans text-light-200 text-lg'>
        {loading ? <span className='text-2xl font-dm-sans p-5'>
          <svg aria-hidden="true" class="w-8 h-8 text-gray-200 animate-spin dark:text-gray-600 fill-blue-600" viewBox="0 0 100 101" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M100 50.5908C100 78.2051 77.6142 100.591 50 100.591C22.3858 100.591 0 78.2051 0 50.5908C0 22.9766 22.3858 0.59082 50 0.59082C77.6142 0.59082 100 22.9766 100 50.5908ZM9.08144 50.5908C9.08144 73.1895 27.4013 91.5094 50 91.5094C72.5987 91.5094 90.9186 73.1895 90.9186 50.5908C90.9186 27.9921 72.5987 9.67226 50 9.67226C27.4013 9.67226 9.08144 27.9921 9.08144 50.5908Z" fill="currentColor"/>
              <path d="M93.9676 39.0409C96.393 38.4038 97.8624 35.9116 97.0079 33.5539C95.2932 28.8227 92.871 24.3692 89.8167 20.348C85.8452 15.1192 80.8826 10.7238 75.2124 7.41289C69.5422 4.10194 63.2754 1.94025 56.7698 1.05124C51.7666 0.367541 46.6976 0.446843 41.7345 1.27873C39.2613 1.69328 37.813 4.19778 38.4501 6.62326C39.0873 9.04874 41.5694 10.4717 44.0505 10.1071C47.8511 9.54855 51.7191 9.52689 55.5402 10.0491C60.8642 10.7766 65.9928 12.5457 70.6331 15.2552C75.2735 17.9648 79.3347 21.5619 82.5849 25.841C84.9175 28.9121 86.7997 32.2913 88.1811 35.8758C89.083 38.2158 91.5421 39.6781 93.9676 39.0409Z" fill="currentFill"/>
          </svg>
        </span> :
          (error ? <span className='text-red-500 text-2xl'>Some Error Occured while Fetching Prediction Data , Please try again later !</span> :
          (<div id='para' className='m-10 gap-3 flex flex-col justify-start items-start'>
            <span>{predictionDetail.prediction}</span>
            <ul>
              {predictionDetail.info.map((inference)=>(
                <li key={inference}>
                  <span>{`• ${inference}`}</span>
                </li>
              ))}
            </ul>
            <span>{predictionDetail.url}</span>
          </div>)
          )
        }
        
        <div className='w-full px-5 lg:px-60 text-xl text-zinc-200 transition-all translate-y-6 ease-out duration-100'>
          <Search 
            searchTerm={searchTerm} 
            setSearchTerm={setSearchTerm}  
            handlePrediction={handlePrediction}
            setLoading={setLoading}
          />
        </div>
      </div>
    </main>
  );
}

export default Home;