import PostPreview from '@/components/PostPreview';
import getPostMetadata from '@/components/getPostMetadata';
import Link from 'next/link';


const Writeups = () => {
    const postsMetadata = getPostMetadata();
    const postsPreview = postsMetadata.map((post) => {
        return (
            <PostPreview key={post.slug} {...post} />
        );
    });
    return (
        <div className='grid grid-cols-1 md:grid-cols-2 gap-4'>
            {postsPreview}
        </div>
    );
};

export default Writeups;
