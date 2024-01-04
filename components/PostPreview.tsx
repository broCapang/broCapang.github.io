import Link from "next/link";
import { PostsMetadata } from "./PostsMetadata";

const PostPreview = (props: PostsMetadata) => {
    return (
        <div className="border border-slate-600 p-6 rounded-md shadow-sm bg-slate-800">
            <h2 className="text-white hover:underline mb-4 font-bold">
                <Link href={`posts/${props.slug}`}>
                    {props.title}
                </Link>
            </h2>
            <p>Category: {props.category}</p>
            <p>Tag: {props.tag}</p>
        </div>
    );
}
export default PostPreview;