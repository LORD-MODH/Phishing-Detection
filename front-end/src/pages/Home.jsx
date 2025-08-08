import { useEffect, useMemo, useState, useRef } from 'react';
import { gsap } from 'gsap';
// TextPlugin is no longer needed for this approach
import Search from '../components/Search';

const Home = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [submitText,setSubmitText] = useState('');
  const typedTextRef = useRef(null);
  const cursorRef = useRef(null);

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

  return (
    <main className='w-screen h-screen flex flex-col bg-primary '>
      <header className='p-4 pl-10 pt-7 flex justify-center sm:justify-start text-light-200 font-dm-sans'>
        <span className='text-2xl font-dm-sans'>PHISHTECT</span>
      </header>
      <div className='p-4 m-4 mt-20 inline-flex justify-center items-center text-3xl md:text-5xl font-dm-sans font-bold h-20'>
        <span className='text-gradient' ref={typedTextRef}></span>
        {/* <span className="text-white animate-blink" ref={cursorRef} style={{ opacity: 0 }}>&#9474;</span> */}
      </div>
      <div className='p-20 flex flex-col justify-end items-center font-dm-sans text-light-200'>
        <div className='m-10'>
          {submitText}
        </div>
        <div className='w-full px-5 lg:px-60 text-xl text-zinc-200'>
          <Search searchTerm={searchTerm} setSearchTerm={setSearchTerm} setSubmitText={setSubmitText}/>
        </div>
      </div>
    </main>
  );
}

export default Home;